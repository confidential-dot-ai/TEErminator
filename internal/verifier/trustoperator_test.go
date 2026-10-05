package verifier

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// operatorSignatureVector is minted by c8s pkg/operatorauth: a write token
// over a canonical policy and the key-set hash a rollout state names.
//
//go:embed testdata/operator_signature_vector.json
var operatorSignatureVector []byte

func TestOperatorSignatureVector(t *testing.T) {
	var v struct {
		OperatorKeysPEM  string `json:"operator_keys_pem"`
		OperatorKeysHash string `json:"operator_keys_hash"`
		PolicyB64        string `json:"policy_b64"`
		Token            string `json:"token"`
	}
	if err := json.Unmarshal(operatorSignatureVector, &v); err != nil {
		t.Fatal(err)
	}
	keys, err := parseOperatorKeys([]byte(v.OperatorKeysPEM))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := keySetHash(keys); err != nil || got != v.OperatorKeysHash {
		t.Fatalf("keySetHash = %s, %v; want %s", got, err, v.OperatorKeysHash)
	}
	policy, err := base64.StdEncoding.DecodeString(v.PolicyB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWriteToken(keys, v.Token, policy); err != nil {
		t.Fatalf("verifyWriteToken(the signed policy) = %v", err)
	}
	if err := verifyWriteToken(keys, v.Token, append(policy, ' ')); err == nil {
		t.Fatal("verifyWriteToken accepted another policy")
	}
	parts := strings.Split(v.Token, ".")
	if err := verifyWriteToken(keys, parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(make([]byte, 64)), policy); err == nil {
		t.Fatal("verifyWriteToken accepted a forged signature")
	}
}

// RTMR[3] may be expected_rtmr3 followed by a prefix of the measured list,
// which becomes the verdict's history.
func TestEnforceReplaysMeasuredPolicies(t *testing.T) {
	var seed [RegisterSize]byte
	seed[0] = 0x5e
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	reg := extendRegister(seed, p)
	res := &teetypes.VerificationResult{Claims: teetypes.Claims{PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])}}}
	pins := platformPins{rtmr3: &seed}
	for _, tc := range []struct {
		name     string
		measured []string
		history  []string
		ok       bool
	}{
		{"list ahead of the quote", []string{p, q}, []string{p}, true},
		{"list that does not replay", []string{q}, nil, false},
		{"no list", nil, nil, false},
	} {
		v := &SessionVerdict{}
		err := pins.enforce(teetypes.PlatformTDX, res, v, tc.measured)
		if (err == nil) != tc.ok || !slices.Equal(v.MeasuredPolicies, tc.history) {
			t.Errorf("%s: enforce = %v (history %v), want ok=%v history %v", tc.name, err, v.MeasuredPolicies, tc.ok, tc.history)
		}
	}
	st := &rolloutState{Bound: []string{p}, Lease: 30}
	if err := checkPinnedPolicies(st, []string{p}, []string{q, p}); err == nil || !strings.Contains(err.Error(), "since boot") {
		t.Fatalf("checkPinnedPolicies with an unpinned history = %v, want the history error", err)
	}
}
