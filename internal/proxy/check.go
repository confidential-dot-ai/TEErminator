package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
)

// CheckResult is the outcome of a live trust check for one remote.
type CheckResult struct {
	Status config.TrustStatus
	// Detail explains the status: the verified measurement for StatusVerified,
	// the failure reason for StatusFailed.
	Detail string
}

// CheckRemote actively determines the remote's trust status right now, using
// the same upstream TLS trust (ServerName override + operator CAs) the proxy
// forwards over:
//   - AttestEndpoint (Flow B): run the session-start attestation; Verified on
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
	tlsCfg, err := upstreamTLSConfig(target, r, extraCAs)
	if err != nil {
		return CheckResult{config.StatusFailed, err.Error()}
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	origin := target.Scheme + "://" + target.Host

	switch r.Mode {
	case config.AttestEndpoint:
		ea, err := verifier.NewEndpointAttester(origin, client, r, tlsCfg.RootCAs)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		v, err := ea.Attest(ctx)
		if err != nil {
			return CheckResult{config.StatusFailed, err.Error()}
		}
		detail := "measurement " + v.Measurement
		if len(r.Measurements) == 0 {
			detail += " (no --measurements allowlist: workload identity not pinned)"
		}
		return CheckResult{config.StatusVerified, detail}
	case config.AttestNone:
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
