package verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// extendRegister folds one policy digest into a TDX RTMR value the way the
// c8s NRI plugin measures it (attestation-go runtimemeasure): the event is
// SHA-384 of the canonical "sha256:<hex>" string, and the register becomes
// SHA-384(register || event).
func extendRegister(reg [RegisterSize]byte, digest string) [RegisterSize]byte {
	event := sha512.Sum384([]byte(digest))
	return sha512.Sum384(append(reg[:], event[:]...))
}

// keySetDomain prefixes the c8s operator key-set hash
// (pkg/operatorauth.KeySetDigest).
const keySetDomain = "c8s-operator-key-set-v1\x00"

// keySetHash is c8s's operatorauth.KeySetHash: hex SHA-256 over the domain
// and the sorted, deduplicated SHA-256 fingerprints of each key's PKIX DER.
func keySetHash(keys []*ecdsa.PublicKey) (string, error) {
	var fps [][]byte
	for _, k := range keys {
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", err
		}
		fp := sha256.Sum256(der)
		fps = append(fps, fp[:])
	}
	slices.SortFunc(fps, bytes.Compare)
	h := sha256.New()
	h.Write([]byte(keySetDomain))
	var prev []byte
	for _, fp := range fps {
		if !bytes.Equal(fp, prev) {
			h.Write(fp)
		}
		prev = fp
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func parseOperatorKeys(pemBytes []byte) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("operator keys: %w", err)
		}
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("operator keys: %T is not an EC key", pub)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("operator keys: no PUBLIC KEY block")
	}
	return keys, nil
}

// maxTokenValidity is c8s operatorauth.MaxTokenValidity.
const maxTokenValidity = 5 * time.Minute

// verifyWriteToken checks a stored c8s operator write token: an ES256/384/512
// JWS under one of keys whose htm, htu and pbh claims bind it to PUT
// /allowlist with body. Its expiry is not checked, since CDS enforced it when
// it accepted the write.
func verifyWriteToken(keys []*ecdsa.PublicKey, token string, body []byte) error {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return fmt.Errorf("signature is not a compact JWS")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := decodeJSONPart(parts[0], &header); err != nil {
		return err
	}
	hashes := map[string]crypto.Hash{"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512}
	hash, ok := hashes[header.Alg]
	if !ok {
		return fmt.Errorf("signature algorithm %q is not ES256, ES384 or ES512", header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig)%2 != 0 {
		return fmt.Errorf("malformed JWS signature")
	}
	h := hash.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	digest := h.Sum(nil)
	r, s := new(big.Int).SetBytes(sig[:len(sig)/2]), new(big.Int).SetBytes(sig[len(sig)/2:])
	if !slices.ContainsFunc(keys, func(k *ecdsa.PublicKey) bool { return ecdsa.Verify(k, digest, r, s) }) {
		return fmt.Errorf("signature does not verify under the operator key set")
	}
	var claims struct {
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		PBH string `json:"pbh"`
		IAT int64  `json:"iat"`
		EXP int64  `json:"exp"`
	}
	if err := decodeJSONPart(parts[1], &claims); err != nil {
		return err
	}
	if v := time.Duration(claims.EXP-claims.IAT) * time.Second; claims.IAT <= 0 || v <= 0 || v > maxTokenValidity {
		return fmt.Errorf("signature token validity is outside (0, %s]", maxTokenValidity)
	}
	sum := sha256.Sum256(body)
	if claims.HTM != http.MethodPut || claims.HTU != "/allowlist" || claims.PBH != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return fmt.Errorf("signature does not authorize PUT /allowlist with this policy")
	}
	return nil
}

func decodeJSONPart(part string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return fmt.Errorf("malformed JWS: %w", err)
	}
	return json.Unmarshal(b, v)
}

// checkOperatorSignatures requires every policy in the bound and the node's
// measured history to carry the operator's signature under the key set the
// attested state names.
func (e *EndpointAttester) checkOperatorSignatures(ctx context.Context, st *rolloutState, history []string) error {
	var keysPEM []byte
	var err error
	if e.remote.OperatorKeysPath != "" {
		keysPEM, err = os.ReadFile(e.remote.OperatorKeysPath)
	} else {
		keysPEM, err = e.fetchWellKnown(ctx, "/.well-known/c8s/operator-keys")
	}
	if err != nil {
		return fmt.Errorf("operator keys: %w", err)
	}
	keys, err := parseOperatorKeys(keysPEM)
	if err != nil {
		return err
	}
	if hash, err := keySetHash(keys); err != nil || hash != st.OperatorKeys {
		return fmt.Errorf("the attested state names operator key set %q, not this one (%s)", st.OperatorKeys, hash)
	}
	policies := slices.Clone(st.Bound)
	for _, d := range history {
		if !slices.Contains(policies, d) {
			policies = append(policies, d)
		}
	}
	for _, d := range policies {
		if !policyDigestRE.MatchString(d) {
			return fmt.Errorf("malformed policy digest %q", d)
		}
		object := "/.well-known/c8s/objects/sha256/" + strings.TrimPrefix(d, "sha256:")
		body, err := e.fetchWellKnown(ctx, object)
		if err != nil {
			return fmt.Errorf("policy %s: %w", d, err)
		}
		if sum := sha256.Sum256(body); "sha256:"+hex.EncodeToString(sum[:]) != d {
			return fmt.Errorf("the router served bytes for %s that do not match it", d)
		}
		token, err := e.fetchWellKnown(ctx, object+"/signature")
		if err != nil {
			return fmt.Errorf("policy %s carries no operator signature: %w", d, err)
		}
		if err := verifyWriteToken(keys, string(token), body); err != nil {
			return fmt.Errorf("policy %s: %w", d, err)
		}
	}
	return nil
}

// fetchWellKnown GETs path on the router origin over the attested client.
func (e *EndpointAttester) fetchWellKnown(ctx context.Context, path string) ([]byte, error) {
	u := *e.attestURL
	u.Path, u.RawQuery = path, ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}
