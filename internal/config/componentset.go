package config

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// componentSetVersionPattern is the MAJOR.MINOR.PATCH grammar of the mesh
// leaf's component-set extension (C8s pkg/armtls/componentset.go).
var componentSetVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseComponentSetPin parses a component_set entry,
// "<version>[@sha256:<64 lowercase hex>]". digest is nil when the entry names
// the version alone.
func ParseComponentSetPin(s string) (version string, digest []byte, err error) {
	version, rest, hasDigest := strings.Cut(s, "@")
	if !componentSetVersionPattern.MatchString(version) {
		return "", nil, fmt.Errorf("--component-set %q: version %q is not MAJOR.MINOR.PATCH", s, version)
	}
	if !hasDigest {
		return version, nil, nil
	}
	hexDigest, ok := strings.CutPrefix(rest, "sha256:")
	if !ok || !lowerHex64.MatchString(hexDigest) {
		return "", nil, fmt.Errorf("--component-set %q: digest %q is not sha256:<64 lowercase hex>", s, rest)
	}
	digest, _ = hex.DecodeString(hexDigest) // lowerHex64 matched
	return version, digest, nil
}

// validateComponentSets rejects a stored component_set that is malformed or
// that r's mode never enforces, so a hand-edited pin fails at load rather than
// reading as configured.
func (r *Remote) validateComponentSets() error {
	if len(r.ComponentSets) == 0 {
		return nil
	}
	if r.Mode != AttestEndpoint {
		return fmt.Errorf("component_set requires mode %q, got %q", AttestEndpoint, r.Mode)
	}
	for _, p := range r.ComponentSets {
		if _, _, err := ParseComponentSetPin(p); err != nil {
			return err
		}
	}
	return nil
}
