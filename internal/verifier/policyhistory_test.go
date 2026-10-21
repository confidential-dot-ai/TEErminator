package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// otherAllowlistRaw is a second policy document a node may have enforced.
var otherAllowlistRaw = []byte(`{"schema":"c8s.allowlist/v1","workloads":{"api":{"containers":[]},"batch":{"containers":[]}}}`)

func policyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// historyNode is a measuring TDX node that enforced docs in order since a boot
// seeded with anchor.
type historyNode struct {
	anchorPath string
	seed       [RegisterSize]byte
	docs       map[string][]byte
	history    []string
	rtmr3      string
}

func newHistoryNode(t *testing.T, docs ...[]byte) *historyNode {
	t.Helper()
	_, vec := loadMeasuredPoliciesVector(t)
	n := &historyNode{
		anchorPath: filepath.Join(t.TempDir(), "operator.pub"),
		seed:       runtimemeasure.Seed([]byte(vec.AnchorPEM)),
		docs:       map[string][]byte{},
	}
	if err := os.WriteFile(n.anchorPath, []byte(vec.AnchorPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		digest := policyDigest(d)
		n.docs[strings.TrimPrefix(digest, "sha256:")] = d
		n.history = append(n.history, digest)
	}
	reg := runtimemeasure.FromDigestsSeeded(n.seed, n.history)
	n.rtmr3 = hex.EncodeToString(reg[:])
	return n
}

// remote pins the image and derives the RTMR[3] seed from the operator key.
func (n *historyNode) remote(t *testing.T) config.Remote {
	return config.Remote{Mode: config.AttestEndpoint, ImageManifestPath: pinManifest(t), OperatorPubkeyPath: n.anchorPath}
}

// signer serves each stored document and a write token for it signed by key;
// unsigned lists the digests stored without a token.
type signer struct {
	node     *historyNode
	key      *ecdsa.PrivateKey
	tamper   string
	unsigned string
}

func (s signer) serve(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, allowlistObjects)
		hexDigest, sig := strings.CutSuffix(rest, "/signature")
		doc, ok := s.node.docs[hexDigest]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch {
		case !sig && hexDigest == s.tamper:
			_, _ = w.Write(append([]byte(" "), doc...))
		case !sig:
			_, _ = w.Write(doc)
		case hexDigest == s.unsigned:
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte(allowlistToken(t, s.key, doc) + "\n"))
		}
	}
}

// allowlistToken is the write token of a signed PUT /allowlist of doc.
func allowlistToken(t *testing.T, key *ecdsa.PrivateKey, doc []byte) string {
	t.Helper()
	sum := sha256.Sum256(doc)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"htm":"PUT","htu":"/allowlist","pbh":%q,"iat":1,"exp":61}`, base64.RawURLEncoding.EncodeToString(sum[:])))
	digest := sha256.Sum256([]byte(header + "." + payload))
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAttestLBPolicyHistory(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := newHistoryNode(t, otherAllowlistRaw, defaultAllowlistRaw)
	leaf := policyDigest(defaultAllowlistRaw)
	otherOnly := newHistoryNode(t, otherAllowlistRaw)
	pinnedFile := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(pinnedFile, otherAllowlistRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	trust := func(r config.Remote, k *ecdsa.PrivateKey) config.Remote {
		r.TrustOperator, r.TrustOperatorKeys = true, []string{operatorKeyPEM(t, k)}
		return r
	}
	pin := func(r config.Remote, entries ...string) config.Remote {
		r.PinnedPolicies = entries
		return r
	}
	for _, tc := range []struct {
		name        string
		remote      config.Remote
		rtmr3       string // quoted register; default the node's
		specific    bool   // pin the mesh CA
		noStamp     bool
		signer      signer
		wantErr     string
		wantCheck   string
		wantPartial string // substring of NotProven; empty wants a full verdict
	}{
		{name: "unjudged history is partial", remote: node.remote(t), wantCheck: PolicyUnchecked, wantPartial: "none was judged"},
		{name: "pinned digests", remote: pin(node.remote(t), node.history...), specific: true, wantCheck: PolicyPinned},
		{name: "pinned file and digest", remote: pin(node.remote(t), pinnedFile, leaf), specific: true, wantCheck: PolicyPinned},
		{name: "pinned without a mesh CA pin is partial", remote: pin(node.remote(t), node.history...), wantCheck: PolicyPinned, wantPartial: "CA-vouched"},
		{name: "pinned with an unstamped leaf is partial", remote: pin(node.remote(t), node.history...), specific: true, noStamp: true, wantCheck: PolicyPinned, wantPartial: "no matched-workload stamp"},
		{name: "history entry not pinned", remote: pin(node.remote(t), leaf), wantErr: "policy_history_not_pinned: the node enforced policy " + node.history[0]},
		{name: "leaf policy not pinned", remote: pin(otherOnly.remote(t), node.history[0]), rtmr3: otherOnly.rtmr3, wantErr: "policy_history_not_pinned: the mesh leaf was issued under policy " + leaf},
		{name: "pinned against a node that does not measure", remote: pin(node.remote(t), node.history...), rtmr3: hex.EncodeToString(node.seed[:]), wantErr: "policy_history_absent"},
		{name: "operator signed", remote: trust(node.remote(t), key), specific: true, signer: signer{node: node, key: key}, wantCheck: PolicyOperatorSigned},
		{name: "operator signed without a mesh CA pin is partial", remote: trust(node.remote(t), key), signer: signer{node: node, key: key}, wantCheck: PolicyOperatorSigned, wantPartial: "CA-vouched"},
		{name: "signed by another key", remote: trust(node.remote(t), key), signer: signer{node: node, key: other}, wantErr: "policy_history_unsigned"},
		{name: "unsigned policy", remote: trust(node.remote(t), key), signer: signer{node: node, key: key, unsigned: strings.TrimPrefix(node.history[0], "sha256:")}, wantErr: "policy_history_unsigned: policy " + node.history[0] + " carries no operator signature"},
		{name: "unsigned leaf policy outside the history", remote: trust(node.remote(t), key), rtmr3: otherOnly.rtmr3, specific: true, signer: signer{node: node, key: key, unsigned: strings.TrimPrefix(leaf, "sha256:")}, wantErr: "policy_history_unsigned: policy " + leaf},
		{name: "served bytes do not hash to the digest", remote: trust(node.remote(t), key), signer: signer{node: node, key: key, tamper: strings.TrimPrefix(leaf, "sha256:")}, wantErr: "allowlist_digest_mismatch"},
		{name: "operator trust against a node that does not measure", remote: trust(node.remote(t), key), rtmr3: hex.EncodeToString(node.seed[:]), signer: signer{node: node, key: key}, wantErr: "policy_history_absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := tdxStubClaims()
			sc.platformData["rtmr_3"] = node.rtmr3
			if tc.rtmr3 != "" {
				sc.platformData["rtmr_3"] = tc.rtmr3
			}
			stubEvidenceClaims(t, sc)
			f := newLBFixture(t, fixtureOpts{noStamp: tc.noStamp})
			spec := bundleSpec{platform: "tdx", measuredPolicies: node.history}
			if tc.signer.node != nil {
				spec.objects = tc.signer.serve(t)
			}
			ts := f.newServer(t, spec)
			var pinned []*x509.Certificate
			if tc.specific {
				pinned = []*x509.Certificate{f.ca.cert}
			}
			v, err := newLBAttester(t, ts, tc.remote, pinned).Attest(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Attest() = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Attest() = %v", err)
			}
			if v.PolicyCheck != tc.wantCheck {
				t.Errorf("PolicyCheck = %q, want %q", v.PolicyCheck, tc.wantCheck)
			}
			notProven := strings.Join(v.NotProven, "; ")
			if v.Partial != (tc.wantPartial != "") || !strings.Contains(notProven, tc.wantPartial) {
				t.Errorf("Partial, NotProven = %t, %q, want partial naming %q", v.Partial, notProven, tc.wantPartial)
			}
		})
	}
}

func TestAttestLBSignedPolicyCache(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := newHistoryNode(t, defaultAllowlistRaw)
	sc := tdxStubClaims()
	sc.platformData["rtmr_3"] = node.rtmr3
	stubEvidenceClaims(t, sc)
	f := newLBFixture(t, fixtureOpts{})
	var fetches atomic.Int32
	serve := signer{node: node, key: key}.serve(t)
	ts := f.newServer(t, bundleSpec{platform: "tdx", measuredPolicies: node.history, objects: func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		serve(w, r)
	}})
	r := node.remote(t)
	r.TrustOperator, r.TrustOperatorKeys = true, []string{operatorKeyPEM(t, key)}
	ea := newLBAttester(t, ts, r, nil)
	for range 2 {
		if _, err := ea.Attest(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := fetches.Load(); n != 2 {
		t.Errorf("fetches = %d, want 2: a verified document and token are fetched once per attester", n)
	}
}
