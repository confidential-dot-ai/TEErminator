// Package routes verifies the signed route manifest a c8s router publishes at
// /.well-known/c8s/routes: the operator's write token over the exact manifest
// bytes, the manifest schema, and the revision rule against the last
// manifest a client accepted.
//
// The parser follows the c8s pkg/routes package rule for rule; a manifest c8s
// rejects is rejected here. It keeps only what a client checks: the revision
// and the routed host names.
package routes

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Schema identifies the manifest format.
const Schema = "c8s.routes/v1"

const (
	maxRevision      = 1<<53 - 1
	maxMaxAgeSeconds = 1<<31 - 1
	maxWorkloadName  = 63
)

// Manifest is the part of a validated route manifest a client checks.
type Manifest struct {
	Revision uint64
	// Hosts holds the lower-case host names the manifest routes.
	Hosts []string
}

// Routes reports whether the manifest has routes for host, which may carry a
// port. Like the router, it drops the port and lower-cases ASCII letters only.
func (m *Manifest) Routes(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	b := []byte(host)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return slices.Contains(m.Hosts, string(b))
}

// Digest returns the route digest of manifest bytes: SHA-256 of exactly
// those bytes.
func Digest(manifest []byte) [sha256.Size]byte {
	return sha256.Sum256(manifest)
}

// Parse validates manifest bytes against the c8s.routes/v1 schema and
// rejects the whole manifest on the first failure.
func Parse(manifest []byte) (*Manifest, error) {
	m, err := parse(manifest)
	if err != nil {
		return nil, fmt.Errorf("route manifest: %w", err)
	}
	return m, nil
}

func parse(data []byte) (*Manifest, error) {
	if err := validateJSON(data); err != nil {
		return nil, err
	}
	top, err := members(data, "manifest", []string{"schema", "revision", "notBefore", "maxAgeSeconds", "hosts"}, nil)
	if err != nil {
		return nil, err
	}
	schema, err := stringValue(top["schema"], "schema")
	if err != nil {
		return nil, err
	}
	if schema != Schema {
		return nil, fmt.Errorf("schema: got %q, want %q", schema, Schema)
	}
	var m Manifest
	if m.Revision, err = integer(top["revision"], "revision", maxRevision); err != nil {
		return nil, err
	}
	notBefore, err := stringValue(top["notBefore"], "notBefore")
	if err != nil {
		return nil, err
	}
	if err := checkTimestamp(notBefore); err != nil {
		return nil, fmt.Errorf("notBefore: %w", err)
	}
	if _, err := integer(top["maxAgeSeconds"], "maxAgeSeconds", maxMaxAgeSeconds); err != nil {
		return nil, err
	}
	if m.Hosts, err = parseHosts(top["hosts"]); err != nil {
		return nil, err
	}
	return &m, nil
}

// dateTime is the RFC 3339 §5.6 date-time grammar. time.Parse alone also
// accepts one-digit fields, comma fractions and offsets such as +24:00.
var dateTime = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:)(\d{2})(\.\d+)?([Zz]|[+-]([01]\d|2[0-3]):[0-5]\d)$`)

// checkTimestamp checks an RFC 3339 date-time; time.Parse checks the field
// ranges. A leap second is valid only at 23:59:60 UTC on 30 June or
// 31 December.
func checkTimestamp(s string) error {
	m := dateTime.FindStringSubmatch(s)
	if m == nil {
		return errors.New("not an RFC 3339 date-time")
	}
	leap := m[2] == "60"
	if leap {
		m[2] = "59"
	}
	t, err := time.Parse(time.RFC3339, strings.ToUpper(m[1]+m[2]+m[3]+m[4]))
	if err != nil || !leap {
		return err
	}
	u := t.UTC()
	_, month, day := u.Date()
	halfYearEnd := month == time.June && day == 30 || month == time.December && day == 31
	if !halfYearEnd || u.Hour() != 23 || u.Minute() != 59 {
		return errors.New("second 60 is only valid at 23:59 UTC on 30 June or 31 December")
	}
	return nil
}

func parseHosts(raw json.RawMessage) ([]string, error) {
	if !isKind(raw, '{') {
		return nil, errors.New("hosts: must be an object")
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}
	// Sorted so that a manifest with several faults always reports the same one.
	names := slices.Sorted(maps.Keys(entries))
	for _, name := range names {
		at := fmt.Sprintf("hosts[%q]", name)
		if err := checkHost(name); err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
		if err := checkHostRoutes(entries[name], at); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func checkHostRoutes(raw json.RawMessage, at string) error {
	obj, err := members(raw, at, []string{"routes"}, nil)
	if err != nil {
		return err
	}
	at += ".routes"
	if !isKind(obj["routes"], '[') {
		return fmt.Errorf("%s: must be a list", at)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(obj["routes"], &items); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}
	if len(items) == 0 {
		return fmt.Errorf("%s: must not be empty", at)
	}
	seen := make(map[[2]string]bool, len(items))
	for i, item := range items {
		path, match, err := checkRoute(item, fmt.Sprintf("%s[%d]", at, i))
		if err != nil {
			return err
		}
		k := [2]string{path, match}
		if seen[k] {
			return fmt.Errorf("%s[%d]: another route has path %q and match %q", at, i, path, match)
		}
		seen[k] = true
	}
	return nil
}

func checkRoute(raw json.RawMessage, at string) (path, match string, err error) {
	obj, err := members(raw, at, []string{"path", "match", "backend"}, nil)
	if err != nil {
		return "", "", err
	}
	if path, err = stringValue(obj["path"], at+".path"); err != nil {
		return "", "", err
	}
	if err := checkRoutePath(path); err != nil {
		return "", "", fmt.Errorf("%s.path: %w", at, err)
	}
	if match, err = stringValue(obj["match"], at+".match"); err != nil {
		return "", "", err
	}
	if match != "exact" && match != "prefix" {
		return "", "", fmt.Errorf("%s.match: got %q, want %q or %q", at, match, "exact", "prefix")
	}
	if err := checkBackend(obj["backend"], at+".backend"); err != nil {
		return "", "", err
	}
	return path, match, nil
}

func checkRoutePath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return errors.New(`must begin with "/"`)
	case strings.ContainsAny(p, "?#%"):
		return errors.New(`must not contain "?", "#" or percent-encoding`)
	case strings.Contains(p, "//"):
		return errors.New(`must not contain "//"`)
	}
	for seg := range strings.SplitSeq(p[1:], "/") {
		if seg == "." || seg == ".." {
			return errors.New(`must not contain a "." or ".." segment`)
		}
	}
	for i := 0; i < len(p); i++ {
		if p[i] != '/' && !pathChar(p[i]) {
			return fmt.Errorf("byte %q at offset %d is not allowed in a URI path", p[i], i)
		}
	}
	return nil
}

// pathChar reports whether c is an RFC 3986 pchar other than an escape.
func pathChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.IndexByte("-._~!$&'()*+,;=:@", c) >= 0
}

// checkBackend accepts a workload backend or an address backend with
// serverName and ca, and nothing else, so no backend skips peer verification.
func checkBackend(raw json.RawMessage, at string) error {
	obj, err := members(raw, at, []string{"address"}, []string{"workload", "serverName", "ca"})
	if err != nil {
		return err
	}
	address, err := stringValue(obj["address"], at+".address")
	if err != nil {
		return err
	}
	if err := checkAddress(address); err != nil {
		return fmt.Errorf("%s.address: %w", at, err)
	}
	_, hasWorkload := obj["workload"]
	_, hasServerName := obj["serverName"]
	_, hasCA := obj["ca"]
	switch {
	case hasWorkload && !hasServerName && !hasCA:
		workload, err := stringValue(obj["workload"], at+".workload")
		if err != nil {
			return err
		}
		if !validWorkloadName(workload) {
			return fmt.Errorf("%s.workload: %q is not a valid allowlist workload name", at, workload)
		}
	case !hasWorkload && hasServerName && hasCA:
		serverName, err := stringValue(obj["serverName"], at+".serverName")
		if err != nil {
			return err
		}
		if !validDNSName(serverName, false) {
			return fmt.Errorf("%s.serverName: %q is not a DNS name", at, serverName)
		}
		if numericFinalLabel(serverName) {
			return fmt.Errorf("%s.serverName: %w", at, errNumericFinalLabel)
		}
		ca, err := stringValue(obj["ca"], at+".ca")
		if err != nil {
			return err
		}
		if err := checkAnchors(ca); err != nil {
			return fmt.Errorf("%s.ca: %w", at, err)
		}
	default:
		return fmt.Errorf("%s: must have exactly one of workload, or serverName with ca", at)
	}
	return nil
}

func validWorkloadName(name string) bool {
	if name == "" || len(name) > maxWorkloadName {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case (b == '.' || b == '_' || b == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

func checkAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("must be host:port")
	}
	if net.ParseIP(host) == nil && !validDNSName(host, false) {
		return fmt.Errorf("host %q is neither an IP address nor a DNS name", host)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 || port[0] == '0' {
		return fmt.Errorf("port %q is not a decimal integer from 1 to 65535", port)
	}
	return nil
}

// checkAnchors requires at least one CERTIFICATE block and nothing else but
// whitespace.
func checkAnchors(bundle string) error {
	const begin = "-----BEGIN "
	n := 0
	rest := []byte(bundle)
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte(begin)) {
			return errors.New("data outside PEM blocks")
		}
		block, next := pem.Decode(rest)
		// pem.Decode skips a malformed block and returns a later one; refuse
		// that rather than ignore the skipped text.
		if block == nil || bytes.Count(rest[:len(rest)-len(next)], []byte(begin)) != 1 {
			return errors.New("malformed PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("PEM block %q is not a CERTIFICATE", block.Type)
		}
		if len(block.Headers) != 0 {
			return errors.New("PEM block has headers")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("certificate %d: %w", n, err)
		}
		n++
		rest = next
	}
	if n == 0 {
		return errors.New("must hold at least one CERTIFICATE block")
	}
	return nil
}

// members decodes a JSON object and requires its member names to be exactly
// required plus any of optional, compared case-sensitively.
func members(raw json.RawMessage, at string, required, optional []string) (map[string]json.RawMessage, error) {
	if !isKind(raw, '{') {
		return nil, fmt.Errorf("%s: must be an object", at)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%s: %w", at, err)
	}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return nil, fmt.Errorf("%s: missing member %q", at, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(obj)) {
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return nil, fmt.Errorf("%s: unknown member %q", at, name)
		}
	}
	return obj, nil
}

func stringValue(raw json.RawMessage, at string) (string, error) {
	var s string
	if !isKind(raw, '"') || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%s: must be a string", at)
	}
	return s, nil
}

// integer accepts a JSON number written as a decimal integer from 1 to
// limit. It rejects 1.0, 1e3 and 01.
func integer(raw json.RawMessage, at string, limit uint64) (uint64, error) {
	s := string(bytes.TrimSpace(raw))
	n, err := strconv.ParseUint(s, 10, 53) // every limit is at most 2^53-1
	if err != nil || s[0] == '0' || n > limit {
		return 0, fmt.Errorf("%s: must be an integer from 1 to %d", at, limit)
	}
	return n, nil
}

func isKind(raw json.RawMessage, first byte) bool {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	return len(raw) > 0 && raw[0] == first
}

var errNumericFinalLabel = errors.New("final label must not be numeric (it would parse as an IPv4 address)")

// checkHost reports whether name can be a manifest host key: a lower-case
// DNS name with no port, trailing dot or numeric final label.
func checkHost(name string) error {
	if net.ParseIP(name) != nil {
		return errors.New("must not be an IP literal")
	}
	if !validDNSName(name, true) {
		return errors.New("not a lower-case DNS host name without port or trailing dot")
	}
	if numericFinalLabel(name) {
		return errNumericFinalLabel
	}
	return nil
}

// numericFinalLabel reports whether a WHATWG URL parser would read name as
// an IPv4 address: its last label is decimal, or 0x followed by hex digits.
func numericFinalLabel(name string) bool {
	last := name[strings.LastIndexByte(name, '.')+1:]
	if len(last) >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X') {
		return strings.Trim(last[2:], "0123456789abcdefABCDEF") == ""
	}
	return strings.Trim(last, "0123456789") == ""
}

// validDNSName reports whether name is an LDH host name of at most 253
// octets with no trailing dot. Non-ASCII names must be written as A-labels.
func validDNSName(name string, lowerOnly bool) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			case c >= 'A' && c <= 'Z' && !lowerOnly:
			default:
				return false
			}
		}
	}
	return true
}
