package verifier

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

func TestFailureMemoKeepsAFailureForItsTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewFailureMemo(time.Minute)
	c.now = func() time.Time { return now }

	if err := c.Failed("host"); err != nil {
		t.Fatalf("Failed() = %v before any attestation", err)
	}
	c.RecordFailure("host", c.Now(), errors.New("boom"))
	now = now.Add(30 * time.Second)
	if err := c.Failed("host"); !failedWith(err, "boom") {
		t.Fatalf("Failed() at 30s = %v, want boom", err)
	}
	now = now.Add(31 * time.Second)
	if err := c.Failed("host"); err != nil {
		t.Fatalf("Failed() past the TTL = %v, want nil", err)
	}
}

// TestRecordKeepsLatestAttempt checks that the verdict of the attestation
// that began last wins, whichever order the verdicts are recorded in.
func TestRecordKeepsLatestAttempt(t *testing.T) {
	now := time.Unix(1000, 0)
	earlier, later := now.Add(-time.Second), now
	for _, tc := range []struct {
		name       string
		record     func(c *FailureMemo)
		wantFailed bool
	}{
		{"failure that began before the pass", func(c *FailureMemo) {
			_ = c.RecordPass("host", later)
			c.RecordFailure("host", earlier, errors.New("boom"))
		}, false},
		{"failure that began after the pass", func(c *FailureMemo) {
			_ = c.RecordPass("host", earlier)
			c.RecordFailure("host", later, errors.New("boom"))
		}, true},
		{"pass that began before the failure", func(c *FailureMemo) {
			c.RecordFailure("host", later, errors.New("boom"))
			_ = c.RecordPass("host", earlier)
		}, true},
		{"pass that began after the failure", func(c *FailureMemo) {
			c.RecordFailure("host", earlier, errors.New("boom"))
			_ = c.RecordPass("host", later)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewFailureMemo(time.Minute)
			c.now = func() time.Time { return now }
			tc.record(c)
			failed := c.Failed("host") != nil
			if failed != tc.wantFailed {
				t.Errorf("Failed() != nil is %v, want %v", failed, tc.wantFailed)
			}
		})
	}
}

// TestRemoteKey checks the cache key covers the endpoint mode and every policy
// pin, and is canonical over measurement order and case.
func TestRemoteKey(t *testing.T) {
	ca := mintCA(t, "key-test-ca")
	otherCA := mintCA(t, "other-key-test-ca")
	base := config.Remote{Mode: config.AttestEndpoint, Measurements: []string{"B2", "a1"}}

	k := RemoteKey("lb.example:443", base, nil, nil)
	if !strings.HasPrefix(k, "lb.example:443|attest-lb|") {
		t.Fatalf("key = %q, want host|mode| prefix", k)
	}
	if k != RemoteKey("lb.example:443", base, nil, nil) {
		t.Fatal("key is not deterministic")
	}
	canon := base
	canon.Measurements = []string{"A1", "b2"}
	if k != RemoteKey("lb.example:443", canon, nil, nil) {
		t.Fatal("key must be invariant under measurement order and case")
	}

	variants := map[string]string{
		"different host": RemoteKey("other.example:443", base, nil, nil),
		"different mode": func() string {
			r := base
			r.Mode = config.AttestCDSCert
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"different measurements": func() string {
			r := base
			r.Measurements = []string{"a1"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"workload pin": func() string {
			r := base
			r.WorkloadName = "api"
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"expected rtmr3": func() string {
			r := base
			r.ExpectedRTMR3 = strings.Repeat("4d", RegisterSize)
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"tcb floor": func() string {
			r := base
			r.MinTCB = &config.TCBFloor{Bootloader: 3, SNP: 8, Microcode: 209}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"other tcb floor": func() string {
			r := base
			r.MinTCB = &config.TCBFloor{Bootloader: 3, SNP: 8, Microcode: 210}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"tdx tcb status": func() string {
			r := base
			r.TDXTCBStatus = []string{"UpToDate"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"wider tdx tcb status": func() string {
			r := base
			r.TDXTCBStatus = []string{"UpToDate", "SWHardeningNeeded"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"route digest pin": func() string {
			r := base
			r.RouteDigests = []string{strings.Repeat("ab", 32)}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"route operator key": func() string {
			r := base
			r.RouteOperatorKeys = []string{"-----BEGIN PUBLIC KEY-----"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"pinned policy": func() string {
			r := base
			r.PinnedPolicies = []string{"sha256:" + strings.Repeat("ab", 32)}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"trust operator": func() string {
			r := base
			r.TrustOperator = true
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"trust operator key": func() string {
			r := base
			r.TrustOperator, r.TrustOperatorKeys = true, []string{"-----BEGIN PUBLIC KEY-----"}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"route floor": func() string {
			r := base
			r.RouteFloor = "3:" + strings.Repeat("ab", 32)
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"rtmr pin": func() string {
			r := base
			r.RTMRs = []string{"1=" + strings.Repeat("4d", RegisterSize)}
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"init data": func() string {
			r := base
			r.InitDataDigest = strings.Repeat("ab", 32)
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"sandbox id": func() string {
			r := base
			r.SandboxID = "sb"
			return RemoteKey("lb.example:443", r, nil, nil)
		}(),
		"pinned file":               RemoteKey("lb.example:443", base, map[string][]byte{"/a": {1, 2, 3}}, nil),
		"other pinned file":         RemoteKey("lb.example:443", base, map[string][]byte{"/b": {1, 2, 3}}, nil),
		"other pinned file content": RemoteKey("lb.example:443", base, map[string][]byte{"/a": {4, 5, 6}}, nil),
		"pinned CA":                 RemoteKey("lb.example:443", base, nil, []*x509.Certificate{ca.cert}),
		"other pinned CA":           RemoteKey("lb.example:443", base, nil, []*x509.Certificate{otherCA.cert}),
	}
	seen := map[string]string{k: "base"}
	for name, key := range variants {
		if prev, dup := seen[key]; dup {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[key] = name
	}

	reordered := base
	reordered.TDXTCBStatus = []string{"SWHardeningNeeded", "UpToDate"}
	if variants["wider tdx tcb status"] != RemoteKey("lb.example:443", reordered, nil, nil) {
		t.Fatal("key must be invariant under TDX TCB status order")
	}

	// Pinned-CA order must not matter.
	a := RemoteKey("h", base, nil, []*x509.Certificate{ca.cert, otherCA.cert})
	b := RemoteKey("h", base, nil, []*x509.Certificate{otherCA.cert, ca.cert})
	if a != b {
		t.Fatal("key must be invariant under pinned-CA order")
	}
}
