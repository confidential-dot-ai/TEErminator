package routes

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Envelope is the wire form of a signed manifest:
// {"manifest": "<standard padded base64 of the manifest bytes>", "token": "<write token>"}.
type Envelope struct {
	Manifest []byte
	// Token is the compact JWS that authorized the write of Manifest.
	Token string
}

// ParseEnvelope decodes an envelope strictly: exactly the members manifest
// and token, no duplicate keys, and manifest in canonical standard padded
// base64, so one envelope has one encoding.
func ParseEnvelope(data []byte) (Envelope, error) {
	if err := validateJSON(data); err != nil {
		return Envelope{}, fmt.Errorf("route envelope: %w", err)
	}
	obj, err := members(data, "route envelope", []string{"manifest", "token"}, nil)
	if err != nil {
		return Envelope{}, err
	}
	encoded, err := stringValue(obj["manifest"], "route envelope: manifest")
	if err != nil {
		return Envelope{}, err
	}
	token, err := stringValue(obj["token"], "route envelope: token")
	if err != nil {
		return Envelope{}, err
	}
	manifest, err := base64.StdEncoding.DecodeString(encoded)
	// DecodeString skips newlines; re-encoding rejects them and any other
	// non-canonical form.
	if err != nil || base64.StdEncoding.EncodeToString(manifest) != encoded {
		return Envelope{}, errors.New("route envelope: manifest is not standard padded base64")
	}
	return Envelope{Manifest: manifest, Token: token}, nil
}

// Signed is a verified signed manifest.
type Signed struct {
	Manifest *Manifest
	Digest   [sha256.Size]byte
}

// MaxTokenValidity is the widest exp−iat window of a write token, matching
// the c8s CDS bound.
const MaxTokenValidity = 5 * time.Minute

// VerifySigned verifies env under the operator keys: the write token (see
// VerifyWriteToken) for PUT /routes over the manifest bytes, then the
// manifest schema.
func VerifySigned(env Envelope, keys []*ecdsa.PublicKey) (*Signed, error) {
	if err := VerifyWriteToken(keys, env.Token, "/routes", env.Manifest); err != nil {
		return nil, fmt.Errorf("verify route write token: %w", err)
	}
	m, err := parseManifest(env.Manifest)
	if err != nil {
		return nil, err
	}
	return &Signed{Manifest: m, Digest: sha256.Sum256(env.Manifest)}, nil
}

// VerifyWriteToken checks a stored c8s operator write token, the rules of
// c8s's operatorauth.VerifyStored: the signature (ES256, ES384 or ES512)
// under one of keys, exp−iat within MaxTokenValidity, htm PUT, htu path and
// pbh against body. It does not compare exp or iat with the clock: the token
// authorized a write that the c8s CDS checked when it happened, and the
// written document outlives its token.
func VerifyWriteToken(keys []*ecdsa.PublicKey, token, path string, body []byte) error {
	claims, err := verifyToken(keys, token)
	if err != nil {
		return err
	}
	// Bounding the window keeps a long-lived token, which CDS would refuse,
	// from authorizing a write here.
	iat, iatOK := claims["iat"].(float64)
	exp, expOK := claims["exp"].(float64)
	if !iatOK || !expOK {
		return errors.New("iat and exp must be numeric dates")
	}
	if validity := time.Duration((exp - iat) * float64(time.Second)); validity <= 0 || validity > MaxTokenValidity {
		return fmt.Errorf("validity %s outside (0, %s]", validity, MaxTokenValidity)
	}
	if htm, _ := claims["htm"].(string); htm != "PUT" {
		return fmt.Errorf("htm %q, want %q", htm, "PUT")
	}
	if htu, _ := claims["htu"].(string); htu != path {
		return fmt.Errorf("htu %q, want %q", htu, path)
	}
	pbh, _ := claims["pbh"].(string)
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare([]byte(pbh), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) != 1 {
		return errors.New("pbh does not match the written bytes")
	}
	return nil
}

// verifyToken checks a compact JWS signature under any of keys and returns
// its claims. The algorithm must match the key's curve.
func verifyToken(keys []*ecdsa.PublicKey, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a compact JWS")
	}
	var header map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || validateJSON(raw) != nil || json.Unmarshal(raw, &header) != nil {
		return nil, errors.New("token header is malformed")
	}
	// No extension is supported, so a critical one must be refused.
	if _, ok := header["crit"]; ok {
		return nil, errors.New("token header carries crit, and no JWS extension is supported")
	}
	alg, _ := header["alg"].(string)
	var (
		hash  crypto.Hash
		curve elliptic.Curve
	)
	switch alg {
	case "ES256":
		hash, curve = crypto.SHA256, elliptic.P256()
	case "ES384":
		hash, curve = crypto.SHA384, elliptic.P384()
	case "ES512":
		hash, curve = crypto.SHA512, elliptic.P521()
	default:
		return nil, fmt.Errorf("token algorithm %q is not ES256, ES384 or ES512", alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	size := (curve.Params().BitSize + 7) / 8
	if err != nil || len(sig) != 2*size {
		return nil, errors.New("token signature is malformed")
	}
	h := hash.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	digest := h.Sum(nil)
	r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
	verified := false
	for _, k := range keys {
		if k.Curve == curve && ecdsa.Verify(k, digest, r, s) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("token is not signed by any pinned operator key")
	}
	var claims map[string]any
	raw, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || validateJSON(raw) != nil || json.Unmarshal(raw, &claims) != nil {
		return nil, errors.New("token claims are malformed")
	}
	return claims, nil
}

// ParsePublicKeys parses one or more PEM PUBLIC KEY blocks holding ECDSA
// P-256, P-384 or P-521 keys. Any other block or trailing data is an error,
// so a private key or a certificate passed by mistake is refused.
func ParsePublicKeys(data []byte) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, errors.New("data outside PEM blocks")
		}
		block, next := pem.Decode(rest)
		// pem.Decode skips a malformed block and returns a later one; refuse
		// that rather than drop a key.
		if block == nil || bytes.Count(rest[:len(rest)-len(next)], []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("malformed PEM block")
		}
		rest = next
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("PEM block %q is not a PUBLIC KEY", block.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse operator public key: %w", err)
		}
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("operator public key is not ECDSA")
		}
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return nil, fmt.Errorf("operator public key curve %s is not P-256, P-384 or P-521", k.Curve.Params().Name)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no PEM PUBLIC KEY block found")
	}
	return keys, nil
}

var (
	// ErrRollback reports a revision lower than the one last accepted.
	ErrRollback = errors.New("route manifest revision is lower than the accepted one")
	// ErrRevisionConflict reports the accepted revision with another digest.
	ErrRevisionConflict = errors.New("route manifest revision equals the accepted one with a different digest")
)

// RollbackError reports a manifest revision lower than the accepted one. It
// matches ErrRollback.
type RollbackError struct {
	Revision, Accepted uint64
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf("%v: %d < %d", ErrRollback, e.Revision, e.Accepted)
}

// Is reports whether target is ErrRollback.
func (e *RollbackError) Is(target error) bool { return target == ErrRollback }

// Floor is the revision and digest of the last signed manifest a client
// accepted. The zero Floor has accepted none. A Floor is safe for concurrent
// use.
type Floor struct {
	mu       sync.Mutex
	revision uint64
	digest   [sha256.Size]byte
}

// Accept raises the floor to s when its revision is higher than the floor's,
// or equal with the same digest, and returns an error otherwise. Checking
// and raising are one step, so concurrent verifications never lower it.
func (f *Floor) Accept(s *Signed) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(s); err != nil {
		return err
	}
	f.revision, f.digest = s.Manifest.Revision, s.Digest
	return nil
}

func (f *Floor) check(s *Signed) error {
	switch r := s.Manifest.Revision; {
	case r < f.revision:
		return &RollbackError{Revision: r, Accepted: f.revision}
	case r == f.revision && s.Digest != f.digest:
		return fmt.Errorf("%w: revision %d", ErrRevisionConflict, r)
	}
	return nil
}
