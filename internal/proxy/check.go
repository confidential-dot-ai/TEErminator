package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
)

// CheckResult is the outcome of a live trust check for one remote.
type CheckResult struct {
	Status config.TrustStatus
	// Detail explains the status: measurement, workload, trust mode, the
	// stamped allowlist version (a claim, labelled as one), and any enforced
	// platform pins (TDX runtime registers, SNP TCB floor) or policy warnings
	// for StatusVerified, the failure reason for StatusFailed.
	Detail string
}

// CheckRemote actively determines the remote's trust status right now, using
// the same trust construction the proxy forwards over:
//   - AttestEndpoint: run the full attest-lb verification; Verified on
//     success, Failed otherwise.
//   - AttestNone: probe the remote over its validated TLS; Untrusted when
//     reachable (nothing attests the workload), Failed when not.
//   - anything else (cds-cert, unknown modes): Failed — the proxy blocks
//     traffic for these, so the remote is not usable as configured.
func CheckRemote(ctx context.Context, r config.Remote, extraCAs []config.Cert) CheckResult {
	target, err := url.Parse(r.Remote)
	if err != nil {
		return CheckResult{config.StatusFailed, fmt.Sprintf("invalid remote URL: %v", err)}
	}
	origin := target.Scheme + "://" + target.Host

	switch r.Mode {
	case config.AttestEndpoint:
		pinnedCAs, err := parseExtraCAs(extraCAs)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		// Same fail-closed trust replacement as the proxy (newH3Transport): the
		// mesh-chained serving cert cannot pass WebPKI verification, so the
		// TLS-layer PKI check is replaced by the attest-lb verification of this
		// very connection, which binds the exact observed leaf into hardware
		// evidence and chains it to the committed CA. No application bytes are
		// sent on this probe.
		tr := &http.Transport{TLSClientConfig: &tls.Config{
			ServerName:         serverNameFor(target, r),
			InsecureSkipVerify: true, // replaced by the attest-lb hardware binding
		}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr}
		ea, err := verifier.NewEndpointAttester(origin, client, r, pinnedCAs)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		v, err := ea.Attest(ctx)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		workload := v.WorkloadName
		if workload == "" {
			workload = "unnamed"
		}
		detail := fmt.Sprintf("measurement %s, workload %s, trust %s (%s)",
			v.Measurement, workload, v.TrustMode, v.Profile)
		// The version counter is what the deployment CLAIMS, read off the
		// stamp; nothing here checked a document against it. Say so, and name
		// the command that does check one, so the claim is not read as a fact.
		if v.AllowlistVersion != "" {
			detail += fmt.Sprintf(", allowlist version %s (claimed by the stamp — `allowlist fetch %s` checks the document behind it)",
				v.AllowlistVersion, r.Local)
		}
		if len(v.RTMRsPinned) > 0 {
			detail += ", rtmrs pinned " + strings.Join(v.RTMRsPinned, " ")
		}
		if v.TCBFloor != "" {
			detail += ", tcb floor " + v.TCBFloor
		}
		if v.Warning != "" {
			detail += " — WARNING: " + v.Warning
		}
		return CheckResult{config.StatusVerified, detail}
	case config.AttestNone:
		tlsCfg, err := upstreamTLSConfig(target, r, extraCAs)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		tr := &http.Transport{TLSClientConfig: tlsCfg}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, origin, nil)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		resp, err := client.Do(req)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		_ = resp.Body.Close()
		// Reachable over validated TLS, but nothing attests the workload.
		return CheckResult{Status: config.StatusUntrusted}
	default:
		return CheckResult{config.StatusFailed,
			fmt.Sprintf("attestation mode %q is not implemented: the proxy blocks all traffic for this remote", r.Mode)}
	}
}

// serverNameFor mirrors upstreamTLSConfig's SNI choice without its trust pool.
func serverNameFor(target *url.URL, r config.Remote) string {
	if r.ServerName != "" {
		return r.ServerName
	}
	return target.Hostname()
}
