- [x] Support TLS Header attestations (Flow A): `remote add --mode tls-header
      --measurements <hex,...>`. The proxy injects `X-Attestation-Nonce`, verifies
      the `Attestation-Report` response header (signature + measurement allowlist +
      nonce binding), and fails closed (drops the response) on failure. See
      `internal/verifier/flow.go`.
- [x] Session-scoped re-attestation: a verified verdict is reused for up to one
      minute (`internal/verifier/cache.go`) so long-lived TLS sessions are not
      re-attested on every request — the TLS channel carries the guarantee between
      periodic freshness checks.
- [ ] Support /attest remote endpoints (Flow B) and `/cds-cert` pinning (Flow C).
      Config model (`Mode`, `Measurements`, `DiscoveryURL`, `Pin`) and the Verifier
      dispatch are in place; each tunnel enforces its own remote's mode, so backends
      can mix methods. Until the Flow B/C clients land, configuring those modes fails
      closed (every response is dropped) rather than forwarding unverified. The Flow
      B/C HTTP clients + `remote pin` / `remote attest` CLI are the remaining work.
      The browser client (`c8s-verify-js`)
      already implements the equivalent over the c8s LB `/.well-known/c8s/*`
      endpoints, so the wire contract is settled (see `c8s-verify-js/PROTOCOL.md`).
- [ ] Decide on WASM vs attestation-go workflows. The browser path uses the
      `attestation-rs` SNP verifier compiled to WASM; TEErminator currently uses
      `go-sev-guest` for the az-snp header path. Converging both on one verifier
      (e.g. the WASM module via wazero, or a shared Go verifier) is open.
