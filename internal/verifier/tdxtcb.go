package verifier

import (
	"fmt"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/google/go-tdx-guest/verify/trust"
)

// Bounds on each Intel PCS collateral fetch (TCB info, QE identity, PCK CRL,
// root CA CRL), so an unreachable PCS fails the attestation instead of
// stalling the request behind it.
const (
	pcsFetchTimeout  = 10 * time.Second
	pcsMaxRetryDelay = 4 * time.Second
)

// ParseTDXTCBStatuses parses the TDX TCB statuses a remote accepts, in Intel
// PCS spelling. Empty input means no policy: TDX evidence is verified offline,
// without collateral. Revoked is never accepted.
func ParseTDXTCBStatuses(statuses []string) ([]teetypes.TdxTcbStatus, error) {
	var out []teetypes.TdxTcbStatus
	for _, s := range statuses {
		status, err := tdx.ParseTCBStatus(s)
		if err != nil {
			return nil, fmt.Errorf("tdx_tcb_status: %w", err)
		}
		if status == teetypes.TdxRevoked {
			return nil, fmt.Errorf("tdx_tcb_status: %s cannot be accepted", status)
		}
		out = append(out, status)
	}
	return out, nil
}

func newIntelPCSGetter() trust.HTTPSGetter {
	return &trust.RetryHTTPSGetter{
		Timeout:       pcsFetchTimeout,
		MaxRetryDelay: pcsMaxRetryDelay,
		Getter:        &trust.SimpleHTTPSGetter{},
	}
}
