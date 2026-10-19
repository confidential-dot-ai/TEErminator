package verifier

// Judging a measuring TDX node's policy history, with the rules of
// `c8s verify --pin-policy` and `--trust-operator`. The RTMR[3] replay proves
// which allowlist policies the node enforced since boot, in order; it does not
// prove any of them acceptable. A remote judges them by pinned digests or by
// the operator's signature over each document, and without either the verdict
// is partial.

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/routes"
)

// Policy checks a verdict can carry in PolicyCheck.
const (
	// PolicyPinned means every judged policy is in pinned_policies.
	PolicyPinned = "pinned"
	// PolicyOperatorSigned means every judged policy document carries an
	// operator write token that verifies under trust_operator_keys.
	PolicyOperatorSigned = "operator-signed"
	// PolicyUnchecked means RTMR[3] replayed a policy history and no check
	// is configured.
	PolicyUnchecked = "unchecked"
)

// allowlistObjects is where CDS serves a stored policy document by digest,
// and its write token at <digest>/signature. The front door proxies it.
const allowlistObjects = "/allowlist/objects/sha256/"

// maxPolicyBytes bounds one fetched policy document, as c8s verify does.
const maxPolicyBytes = 16 << 20

// maxPolicyTokenBytes bounds one fetched write token.
const maxPolicyTokenBytes = 64 << 10

// noHistory explains an empty replayed history.
const noHistory = "no measured policy replayed against RTMR[3]; target a node that measures its policies (nriImagePolicy.measurePolicies)"

// historyPolicy is how a remote judges the node's policy history: by the
// pinned digests, or by the operator keys of trust_operator. The zero value
// judges nothing.
type historyPolicy struct {
	pinned []string
	keys   []*ecdsa.PublicKey
}

// PinnedPolicyDigest resolves one pinned_policies entry: a sha256:<64 hex>
// digest as is, or else the path of an allowlist document, hashed exactly as
// read — the same canonical bytes GET /allowlist serves.
func PinnedPolicyDigest(entry string) (string, error) {
	if canonicalPolicyDigest.MatchString(entry) {
		return entry, nil
	}
	if strings.HasPrefix(entry, "sha256:") {
		return "", fmt.Errorf("pinned policy %q is not sha256:<64 lowercase hex>", entry)
	}
	raw, err := os.ReadFile(entry)
	if err != nil {
		return "", fmt.Errorf("read pinned policy: %w", err)
	}
	if _, err := ParsePinnedAllowlist(raw); err != nil {
		return "", fmt.Errorf("pinned policy %s: %w", entry, err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// loadHistoryPolicy resolves a remote's policy history check, reading every
// pinned file once. ValidatePinCombination has already run.
func loadHistoryPolicy(r config.Remote) (historyPolicy, error) {
	var h historyPolicy
	for _, entry := range r.PinnedPolicies {
		d, err := PinnedPolicyDigest(entry)
		if err != nil {
			return historyPolicy{}, fmt.Errorf("pinned_policies: %w", err)
		}
		h.pinned = append(h.pinned, d)
	}
	for i, e := range r.TrustOperatorKeys {
		k, err := routes.ParsePublicKeys([]byte(e))
		if err != nil {
			return historyPolicy{}, fmt.Errorf("trust_operator_keys[%d]: %w", i, err)
		}
		h.keys = append(h.keys, k...)
	}
	return h, nil
}

// signedPolicies records the policy digests whose document and operator
// token verified under one attester's keys. A digest names its bytes, so a
// verified digest stays verified while the keys stay the same, and the
// attester's keys come from its remote, which never changes.
type signedPolicies struct {
	mu       sync.Mutex
	verified map[string]bool
}

func (s *signedPolicies) has(digest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verified[digest]
}

func (s *signedPolicies) add(digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verified == nil {
		s.verified = make(map[string]bool)
	}
	s.verified[digest] = true
}

// judgePolicyHistory judges v.MeasuredPolicies, the history RTMR[3] replayed,
// and the policy the mesh leaf was issued under, against the remote's pinned
// digests or operator keys. It fails the verdict when a policy is not
// accepted or nothing replayed, and leaves it partial when the history goes
// unjudged, the leaf's issuing policy is unknown or only CA-vouched, or the
// evidence is not bound to this check's nonce (fresh false).
func (e *EndpointAttester) judgePolicyHistory(ctx context.Context, v *SessionVerdict, h historyPolicy, fresh bool) error {
	history, pinned, keys := v.MeasuredPolicies, h.pinned, h.keys
	if len(pinned) == 0 && len(keys) == 0 {
		if len(history) > 0 {
			v.PolicyCheck = PolicyUnchecked
			v.demote(fmt.Sprintf("the node's policy history: RTMR[3] replayed %d measured policies, but none was judged (set pinned_policies or trust_operator)", len(history)))
		}
		return nil
	}
	if len(history) == 0 {
		return fmt.Errorf("policy_history_absent: %s", noHistory)
	}
	leaf := ""
	if v.Stamp != nil {
		leaf = "sha256:" + hex.EncodeToString(v.Stamp.AllowlistDigest)
	}
	if len(pinned) > 0 {
		for _, d := range history {
			if !slices.Contains(pinned, d) {
				return fmt.Errorf("policy_history_not_pinned: the node enforced policy %s since boot and it is not pinned; review it at %s%s", d, allowlistObjects, strings.TrimPrefix(d, "sha256:"))
			}
		}
		if leaf != "" && !slices.Contains(pinned, leaf) {
			return fmt.Errorf("policy_history_not_pinned: the mesh leaf was issued under policy %s, which is not pinned", leaf)
		}
		v.PolicyCheck = PolicyPinned
	} else {
		judged := history
		if leaf != "" && !slices.Contains(history, leaf) {
			judged = append(slices.Clone(history), leaf)
		}
		for _, d := range judged {
			if err := e.checkSignedPolicy(ctx, d, keys); err != nil {
				return err
			}
		}
		v.PolicyCheck = PolicyOperatorSigned
	}
	switch {
	case v.Stamp == nil:
		v.demote(fmt.Sprintf("the policy the mesh leaf was issued under: the policy history is %s, but the leaf carries no matched-workload stamp, so its issuing policy was not checked", v.PolicyCheck))
	case v.TrustMode != TrustSpecificCluster:
		v.demote(fmt.Sprintf("the policy the mesh leaf was issued under: its matched-workload stamp is %s, but the stamp is CA-vouched and the mesh CA is not pinned (certs add)", v.PolicyCheck))
	}
	if !fresh {
		v.demote(fmt.Sprintf("the node's current policy history: the history is %s up to the evidence's quote, which this check's nonce does not bind, so a policy enforced since is not shown", v.PolicyCheck))
	}
	return nil
}

// checkSignedPolicy fetches the policy document digest names from CDS and its
// stored write token, and requires the bytes to hash to digest and the token
// to verify under keys for PUT /allowlist over those bytes. The bytes and the
// token authenticate themselves, so any replica may serve them.
func (e *EndpointAttester) checkSignedPolicy(ctx context.Context, digest string, keys []*ecdsa.PublicKey) error {
	if e.signed.has(digest) {
		return nil
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	body, err := e.fetchPolicyObject(ctx, allowlistObjects+hexDigest, maxPolicyBytes)
	if err != nil {
		return fmt.Errorf("policy_history_unsigned: fetch policy %s: %w", digest, err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != hexDigest {
		return fmt.Errorf("allowlist_digest_mismatch: CDS served bytes for %s that hash to sha256:%x", digest, sum)
	}
	token, err := e.fetchPolicyObject(ctx, allowlistObjects+hexDigest+"/signature", maxPolicyTokenBytes)
	if errors.Is(err, errPolicyNotFound) {
		return fmt.Errorf("policy_history_unsigned: policy %s carries no operator signature; upload the whole document to sign it (c8s allowlist upload)", digest)
	}
	if err != nil {
		return fmt.Errorf("policy_history_unsigned: fetch the signature of %s: %w", digest, err)
	}
	if err := routes.VerifyWriteToken(keys, strings.TrimSpace(string(token)), "/allowlist", body); err != nil {
		return fmt.Errorf("policy_history_unsigned: policy %s: %w", digest, err)
	}
	e.signed.add(digest)
	return nil
}

// errPolicyNotFound is a 404 from fetchPolicyObject.
var errPolicyNotFound = errors.New("not found")

// fetchPolicyObject GETs path at the front door's origin, at most limit bytes.
func (e *EndpointAttester) fetchPolicyObject(ctx context.Context, path string, limit int64) ([]byte, error) {
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("error closing response Body", "error", err)
		}
	}()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errPolicyNotFound
	default:
		return nil, fmt.Errorf("GET %s returned %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s exceeds %d bytes", path, limit)
	}
	return body, nil
}
