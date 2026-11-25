package verifier

// Component-set stamp, vendored from C8s pkg/armtls/componentset.go. The
// Trust Authority places it in the CA-signed area of the mesh leaf, so, like
// the matched-workload stamp, the mesh CA signature vouches for it and the
// hardware evidence does not.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

// oidComponentSet identifies the component-set extension:
//
//	1.3.6.1.4.1.66378.1.11 - component set extension
var oidComponentSet = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 11}

// componentVersionPattern is the MAJOR.MINOR.PATCH grammar the extension
// carries, each a decimal number without a leading zero.
var componentVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ComponentSet names the component set the mesh leaf's pod runs on: the
// release whose component entries admitted its c8s containers.
type ComponentSet struct {
	Version string
	// Digest is SHA-256 of the set's entries, exactly 32 bytes.
	Digest []byte
}

// String renders the set as "<version> sha256:<hex>".
func (c *ComponentSet) String() string {
	return c.Version + " sha256:" + hex.EncodeToString(c.Digest)
}

// componentSetASN1 is the DER encoding:
//
//	ComponentSet ::= SEQUENCE {
//	    version UTF8String,        -- MAJOR.MINOR.PATCH
//	    digest  OCTET STRING (32)  -- SHA-256 of the set's entries
//	}
type componentSetASN1 struct {
	Version string `asn1:"utf8"`
	Digest  []byte
}

func (c *ComponentSet) validate() error {
	if !componentVersionPattern.MatchString(c.Version) {
		return fmt.Errorf("component set version %q is not MAJOR.MINOR.PATCH", c.Version)
	}
	if len(c.Digest) != sha256.Size {
		return fmt.Errorf("component set digest must be %d bytes, got %d", sha256.Size, len(c.Digest))
	}
	return nil
}

// unmarshalComponentSet decodes an extension value, requiring the one
// canonical encoding: no trailing bytes, byte-exact against re-encoding.
func unmarshalComponentSet(der []byte) (*ComponentSet, error) {
	var raw componentSetASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal component set: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%d trailing bytes after component-set extension", len(rest))
	}
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-encode component set: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("component-set extension is not the canonical encoding (%d bytes, canonical is %d)", len(der), len(reencoded))
	}
	set := &ComponentSet{Version: raw.Version, Digest: raw.Digest}
	if err := set.validate(); err != nil {
		return nil, err
	}
	return set, nil
}

// componentSetFromCert returns the certificate's component-set stamp, or nil
// when it carries none. A malformed or duplicated extension is an error, never
// absence. cert must already be chain-verified to the committed mesh CA.
func componentSetFromCert(cert *x509.Certificate) (*ComponentSet, error) {
	var found *ComponentSet
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidComponentSet) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("certificate carries more than one component-set extension")
		}
		set, err := unmarshalComponentSet(ext.Value)
		if err != nil {
			return nil, err
		}
		found = set
	}
	return found, nil
}

// componentSetPin is one parsed component_set entry; digest is nil when the
// pin names the version alone.
type componentSetPin struct {
	version string
	digest  []byte
}

// parseComponentSetPin parses "<version>[@sha256:<64 lowercase hex>]".
func parseComponentSetPin(s string) (componentSetPin, error) {
	version, digest, hasDigest := strings.Cut(s, "@")
	if !componentVersionPattern.MatchString(version) {
		return componentSetPin{}, fmt.Errorf("--component-set %q: version %q is not MAJOR.MINOR.PATCH", s, version)
	}
	if !hasDigest {
		return componentSetPin{version: version}, nil
	}
	hexDigest, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || !lowerHex64.MatchString(hexDigest) {
		return componentSetPin{}, fmt.Errorf("--component-set %q: digest %q is not sha256:<64 lowercase hex>", s, digest)
	}
	b, _ := hex.DecodeString(hexDigest) // lowerHex64 matched
	return componentSetPin{version: version, digest: b}, nil
}

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validateComponentSetPins checks every component_set entry's syntax.
func validateComponentSetPins(pins []string) error {
	for _, p := range pins {
		if _, err := parseComponentSetPin(p); err != nil {
			return err
		}
	}
	return nil
}

// checkComponentSetPins requires got to satisfy one of pins; no pins accepts
// anything, an absent set included.
func checkComponentSetPins(got *ComponentSet, pins []string) error {
	if len(pins) == 0 {
		return nil
	}
	if got == nil {
		return fmt.Errorf("component set pin %s set but the mesh leaf carries no component set", strings.Join(pins, ", "))
	}
	for _, p := range pins {
		pin, err := parseComponentSetPin(p)
		if err != nil {
			return fmt.Errorf("configuration error: %w", err)
		}
		if pin.version == got.Version && (pin.digest == nil || bytes.Equal(pin.digest, got.Digest)) {
			return nil
		}
	}
	return fmt.Errorf("mesh leaf component set %s does not match the pinned %s", got, strings.Join(pins, ", "))
}

// componentSetMismatch reports an allowlist document whose components section
// holds no set of the leaf's version with the leaf's digest. nil when the leaf
// carries no set or the document has no components section.
func (d *PinnedAllowlist) componentSetMismatch(leaf *ComponentSet) error {
	if leaf == nil || len(d.Components) == 0 {
		return nil
	}
	set, ok := d.Components[leaf.Version]
	if !ok {
		return fmt.Errorf("the mesh leaf names component set %s, but the allowlist document holds no set %s (it holds %s)",
			leaf, leaf.Version, strings.Join(slices.Sorted(maps.Keys(d.Components)), ", "))
	}
	digest, err := set.digest()
	if err != nil {
		return fmt.Errorf("the mesh leaf names component set %s, but the document's set %s is unreadable: %w", leaf, leaf.Version, err)
	}
	if !bytes.Equal(digest[:], leaf.Digest) {
		return fmt.Errorf("the mesh leaf names component set %s, but the document's set %s has digest sha256:%x", leaf, leaf.Version, digest)
	}
	return nil
}

// documentSetVersionPattern is the key grammar of a document's component set
// (C8s pkg/allowlist checkComponentVersion): canonical semver of major 0,
// optionally with a pre-release, without the leading v.
var documentSetVersionPattern = regexp.MustCompile(`^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$`)

// deadlineLayout is the one spelling of a retirement deadline (C8s
// pkg/allowlist Deadline).
const deadlineLayout = "2006-01-02T15:04:05Z"

// documentComponentSet is one set of an allowlist document's components
// section. Like C8s's served-document parse, a set that does not decode
// strictly is kept as unreadable and admits nothing, so it never fails the
// document.
type documentComponentSet struct {
	// retire is the deadline from which the set admits nothing; nil when the
	// set is current.
	retire *time.Time
	// entries is the entries value exactly as the document carries it.
	entries json.RawMessage
	names   map[string]json.RawMessage
	// unreadable is why the set cannot be judged.
	unreadable error
}

// UnmarshalJSON never fails; see documentComponentSet.
func (s *documentComponentSet) UnmarshalJSON(data []byte) error {
	var raw struct {
		Retire *struct {
			Deadline string `json:"deadline"`
		} `json:"retire,omitempty"`
		Entries json.RawMessage `json:"entries"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		*s = documentComponentSet{unreadable: err}
		return nil
	}
	if raw.Entries == nil {
		// An absent entries map marshals as null in C8s.
		raw.Entries = json.RawMessage("null")
	}
	if err := json.Unmarshal(raw.Entries, &s.names); err != nil {
		*s = documentComponentSet{unreadable: fmt.Errorf("entries: %w", err)}
		return nil
	}
	s.entries = raw.Entries
	if raw.Retire != nil {
		deadline, err := time.Parse(deadlineLayout, raw.Retire.Deadline)
		if err != nil || deadline.Format(deadlineLayout) != raw.Retire.Deadline {
			*s = documentComponentSet{unreadable: fmt.Errorf("deadline %q is not %s", raw.Retire.Deadline, deadlineLayout)}
			return nil
		}
		s.retire = &deadline
	}
	return nil
}

// inForce reports whether the set admits what it declares at now: it is
// current, or retiring with its deadline still ahead (C8s ComponentSet.InForce).
func (s documentComponentSet) inForce(now time.Time) bool {
	if s.unreadable != nil {
		return false
	}
	return s.retire == nil || now.Before(*s.retire)
}

// digest is C8s ComponentSet.Digest: SHA-256 over json.Marshal of the
// normalized entries, which are the entries bytes of the canonical document.
// Compacting only drops whitespace a pretty-printed copy added.
func (s documentComponentSet) digest() ([sha256.Size]byte, error) {
	if s.unreadable != nil {
		return [sha256.Size]byte{}, s.unreadable
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, s.entries); err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(compact.Bytes()), nil
}

// Resolves reports whether name is an entry of the document a matched-workload
// stamp may name at now: a workloads entry, or an entry of a component set in
// force at now (C8s Allowlist.MatchWorkloadAt).
func (d *PinnedAllowlist) Resolves(name string, now time.Time) bool {
	if _, ok := d.Workloads[name]; ok {
		return true
	}
	for version, set := range d.Components {
		if !documentSetVersionPattern.MatchString(version) || !set.inForce(now) {
			continue
		}
		if _, ok := set.names[name]; ok {
			return true
		}
	}
	return false
}
