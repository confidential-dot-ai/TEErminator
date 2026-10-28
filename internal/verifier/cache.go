package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// FailureMemo remembers a remote's failed attestation for ttl, so a remote
// that fails verification is not attested again on every request. Of
// attestations that race, the one that began last decides.
type FailureMemo struct {
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	state map[string]verdict
}

type verdict struct {
	ok bool
	// started is when the attestation began, verifAt when it was recorded.
	started time.Time
	verifAt time.Time
	err     error
}

// NewFailureMemo returns a memo that keeps a failure for ttl.
func NewFailureMemo(ttl time.Duration) *FailureMemo {
	return &FailureMemo{ttl: ttl, now: time.Now, state: make(map[string]verdict)}
}

// Now returns the time on the memo's clock, for the started argument of
// RecordPass and RecordFailure.
func (c *FailureMemo) Now() time.Time {
	return c.now()
}

// RecordPass records a passing attestation that began at started. It returns
// the remembered failure of an attestation that began later, which stands.
func (c *FailureMemo) RecordPass(key string, started time.Time) error {
	c.record(key, verdict{ok: true, started: started})
	return c.Failed(key)
}

// RecordFailure records a failed attestation that began at started.
func (c *FailureMemo) RecordFailure(key string, started time.Time, err error) {
	c.record(key, verdict{started: started, err: err})
}

// record keeps whichever verdict comes from the attestation that began last,
// so a slow concurrent attestation never replaces newer evidence.
func (c *FailureMemo) record(key string, v verdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if held, ok := c.state[key]; ok && held.started.After(v.started) {
		return
	}
	v.verifAt = c.now()
	c.state[key] = v
}

// Failed returns key's remembered failure, or nil when the latest
// attestation passed or its failure is older than ttl.
func (c *FailureMemo) Failed(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, present := c.state[key]
	if !present {
		return nil
	}
	if !c.remembers(v) {
		return nil
	}
	return v.err
}

// remembers reports whether v is a failure recorded within ttl.
func (c *FailureMemo) remembers(v verdict) bool {
	return !v.ok && c.now().Sub(v.verifAt) <= c.ttl
}

// PinnedFileDigests returns the SHA-256 of every file a remote's pins name,
// keyed by path: the allowlist, the image manifest, the operator public key,
// and the pinned policy documents.
func PinnedFileDigests(r config.Remote) (map[string][]byte, error) {
	paths := []string{r.AllowlistPath, r.ImageManifestPath, r.OperatorPubkeyPath}
	for _, p := range r.PinnedPolicies {
		if !strings.HasPrefix(p, "sha256:") {
			paths = append(paths, p)
		}
	}
	files := make(map[string][]byte)
	for _, p := range paths {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read pinned file: %w", err)
		}
		sum := sha256.Sum256(raw)
		files[p] = sum[:]
	}
	return files, nil
}

// RemoteKey builds the failure-memo key for a remote:
//
//	host + "|" + mode + "|" + hex(SHA-256(policy pins))
//
// where the pin digest covers every pin of r, each length-prefixed with a
// one-byte tag and uint32-BE length, list pins sorted and measurements
// lowercased; the digest of each pinned file (files, from PinnedFileDigests),
// sorted by path; and the sorted pinned-CA DER SHA-256 fingerprints. Every
// policy input is part of the key, so a failure remembered under one policy or
// endpoint mode never refuses traffic under another.
func RemoteKey(host string, r config.Remote, files map[string][]byte, pinnedCAs []*x509.Certificate) string {
	h := sha256.New()
	field := func(tag byte, b []byte) {
		var n [5]byte
		n[0] = tag
		binary.BigEndian.PutUint32(n[1:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	sorted := func(tag byte, values []string) {
		values = slices.Clone(values)
		sort.Strings(values)
		for _, v := range values {
			field(tag, []byte(v))
		}
	}

	meas := make([]string, len(r.Measurements))
	for i, m := range r.Measurements {
		meas[i] = strings.ToLower(m)
	}
	sorted('m', meas)
	field('w', []byte(r.WorkloadName))
	field('r', []byte(strings.ToLower(r.ExpectedRTMR3)))
	if r.MinTCB != nil {
		field('t', fmt.Appendf(nil, "%d,%d,%d,%d",
			r.MinTCB.Bootloader, r.MinTCB.TEE, r.MinTCB.SNP, r.MinTCB.Microcode))
	}
	sorted('x', r.TDXTCBStatus)
	sorted('d', r.RouteDigests)
	sorted('k', r.RouteOperatorKeys)
	field('f', []byte(r.RouteFloor))
	sorted('R', r.RTMRs)
	field('n', []byte(strings.ToLower(r.InitDataDigest)))
	field('s', []byte(r.SandboxID))
	sorted('p', r.PinnedPolicies)
	field('T', []byte(strconv.FormatBool(r.TrustOperator)))
	sorted('o', r.TrustOperatorKeys)
	for _, path := range slices.Sorted(maps.Keys(files)) {
		field('a', []byte(path))
		field('h', files[path])
	}
	fps := make([]string, len(pinnedCAs))
	for i, ca := range pinnedCAs {
		sum := sha256.Sum256(ca.Raw)
		fps[i] = hex.EncodeToString(sum[:])
	}
	sort.Strings(fps)
	for _, fp := range fps {
		field('c', []byte(fp))
	}

	return host + "|" + string(r.Mode) + "|" + hex.EncodeToString(h.Sum(nil))
}
