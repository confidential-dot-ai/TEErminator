package verifier

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// rtmr3Vector is generated with attestation-go runtimemeasure:
// FromDigestsSeeded(Seed(anchor), policies[:i+1]) == rtmr3[i]. c8s-verify-js
// carries the same vector.
//
//go:embed testdata/rtmr3_measured_policies_vector.json
var rtmr3Vector []byte

type measuredPoliciesVector struct {
	AnchorPEM string   `json:"anchor_pem"`
	Seed      string   `json:"seed"`
	Policies  []string `json:"policies"`
	RTMR3     []string `json:"rtmr3"`
}

func loadMeasuredPoliciesVector(t *testing.T) (seed [RegisterSize]byte, vec measuredPoliciesVector) {
	t.Helper()
	if err := json.Unmarshal(rtmr3Vector, &vec); err != nil {
		t.Fatal(err)
	}
	seed = runtimemeasure.Seed([]byte(vec.AnchorPEM))
	if got := hex.EncodeToString(seed[:]); got != vec.Seed {
		t.Fatalf("Seed(anchor) = %s, want %s", got, vec.Seed)
	}
	return seed, vec
}

func rtmr3Result(reg string) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{Claims: teetypes.Claims{PlatformData: map[string]any{"rtmr_3": reg}}}
}

func TestEnforceMeasuredPoliciesGoldenVector(t *testing.T) {
	seed, vec := loadMeasuredPoliciesVector(t)
	pins := platformPins{rtmr3: &seed}
	for i, reg := range vec.RTMR3 {
		v := &SessionVerdict{}
		if err := pins.enforce(teetypes.PlatformTDX, rtmr3Result(reg), v, vec.Policies); err != nil {
			t.Fatalf("enforce(rtmr3 after %d extends) = %v", i+1, err)
		}
		if want := vec.Policies[:i+1]; !slices.Equal(v.MeasuredPolicies, want) {
			t.Errorf("enforce(rtmr3 after %d extends) MeasuredPolicies = %v, want %v", i+1, v.MeasuredPolicies, want)
		}
		if want := []string{"3:" + reg}; !slices.Equal(v.RTMRsPinned, want) {
			t.Errorf("enforce(rtmr3 after %d extends) RTMRsPinned = %v, want %v", i+1, v.RTMRsPinned, want)
		}
	}
}

func TestEnforceMeasuredPolicies(t *testing.T) {
	seed, vec := loadMeasuredPoliciesVector(t)
	d1, d2 := vec.Policies[0], vec.Policies[1]
	seedHex := vec.Seed
	tooMany := make([]string, maxMeasuredPolicies+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("sha256:%064x", i)
	}
	for _, tc := range []struct {
		name     string
		pin      *[RegisterSize]byte
		quoted   string
		measured []string
		want     []string // MeasuredPolicies on success
		wantErr  string
	}{
		{name: "bare seed, no list", pin: &seed, quoted: seedHex},
		{name: "bare seed, list ahead", pin: &seed, quoted: seedHex, measured: []string{d1, d2}},
		{name: "seed plus one", pin: &seed, quoted: vec.RTMR3[0], measured: []string{d1}, want: []string{d1}},
		{name: "seed plus two", pin: &seed, quoted: vec.RTMR3[1], measured: []string{d1, d2}, want: []string{d1, d2}},
		{name: "list ahead of the quote", pin: &seed, quoted: vec.RTMR3[0], measured: []string{d1, d2}, want: []string{d1}},
		{name: "list does not replay", pin: &seed, quoted: vec.RTMR3[1], measured: []string{d2, d1}, wantErr: "do not replay"},
		{name: "no list, register past the seed", pin: &seed, quoted: vec.RTMR3[0], wantErr: "RTMR[3]"},
		{name: "non-canonical entry", pin: &seed, quoted: vec.RTMR3[0], measured: []string{strings.ToUpper(d1)}, wantErr: "not sha256:<64 lowercase hex>"},
		{name: "entry without prefix", pin: &seed, quoted: seedHex, measured: []string{strings.TrimPrefix(d1, "sha256:")}, wantErr: "not sha256:<64 lowercase hex>"},
		{name: "more than 256 entries", pin: &seed, quoted: seedHex, measured: tooMany, wantErr: "more than 256"},
		{name: "no pin ignores the list", quoted: vec.RTMR3[1], measured: []string{"garbage"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &SessionVerdict{}
			err := platformPins{rtmr3: tc.pin}.enforce(teetypes.PlatformTDX, rtmr3Result(tc.quoted), v, tc.measured)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("enforce = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("enforce = %v, want nil", err)
			}
			if !slices.Equal(v.MeasuredPolicies, tc.want) {
				t.Errorf("MeasuredPolicies = %v, want %v", v.MeasuredPolicies, tc.want)
			}
			wantWarn := ""
			if tc.pin == nil && len(tc.measured) > 0 {
				wantWarn = fmt.Sprintf("the evidence lists %d measured policies, but no RTMR[3] seed is pinned (operator_pubkey_path or expected_rtmr3), so they were not replayed or judged", len(tc.measured))
			}
			if v.Warning != wantWarn {
				t.Errorf("Warning = %q, want %q", v.Warning, wantWarn)
			}
		})
	}
}
