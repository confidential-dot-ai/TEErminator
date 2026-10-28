package proxy

import (
	"context"
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
	// for StatusVerified, plus what is not proven for StatusPartial, the
	// failure reason for StatusFailed.
	Detail string
}

// CheckRemote actively determines the remote's trust status right now, using
// the same trust construction the proxy forwards over:
//   - AttestEndpoint: run the full attest-lb verification; Verified on
//     success, Partial when it passed but left a property unproven (such
//     as an unjudged policy history), Failed otherwise.
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
		// Capture the serving leaf first. In cds mode the serving leaf must chain
		// to the committed mesh CA. In acme mode WebPKI verification proves only
		// the certificate's name and issuance — the TEE proof comes from the
		// hardware evidence, which binds the exact serving leaf and the
		// front-door mode into the attested transcript (host-visible `webpki`
		// secrets are rejected there). No application bytes are sent on this
		// probe.
		webPKITLS, err := upstreamTLSConfig(target, r, extraCAs)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		attestTLS := webPKITLS.Clone()
		attestTLS.InsecureSkipVerify = true // trust is checked after the mode is attested
		ea, err := verifier.NewEndpointAttester(target, attestTLS, r, pinnedCAs)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		v, err := ea.Attest(ctx)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		return verdictResult(v, r.Local)
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

// verdictResult reports a passing attest-lb verdict: Partial when it leaves a
// property unproven, Verified otherwise. local names the remote in the hint.
func verdictResult(v *verifier.SessionVerdict, local string) CheckResult {
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
			v.AllowlistVersion, local)
	}
	if len(v.RTMRsPinned) > 0 {
		detail += ", rtmrs pinned " + strings.Join(v.RTMRsPinned, " ")
	}
	if len(v.MeasuredPolicies) > 0 {
		detail += ", measured policies " + strings.Join(v.MeasuredPolicies, " ")
	}
	if v.PolicyCheck != "" {
		detail += ", policy history " + v.PolicyCheck
	}
	if v.SandboxID != "" {
		detail += ", sandbox " + v.SandboxID
	}
	if v.TCBFloor != "" {
		detail += ", tcb floor " + v.TCBFloor
	}
	if v.TDXTCBStatus != "" {
		detail += ", tdx tcb status " + v.TDXTCBStatus
	}
	detail += fmt.Sprintf(", route digest %s (%s", v.RouteDigest, v.RouteCheck)
	if v.RouteRevision != 0 {
		detail += fmt.Sprintf(", revision %d", v.RouteRevision)
	}
	detail += ")"
	if v.Warning != "" {
		detail += " — WARNING: " + v.Warning
	}
	if v.Partial {
		return CheckResult{config.StatusPartial, detail + " — NOT PROVEN: " + strings.Join(v.NotProven, "; ")}
	}
	return CheckResult{config.StatusVerified, detail}
}
