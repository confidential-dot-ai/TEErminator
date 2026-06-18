- [x] Support TLS Header attestations (Flow A): `remote add --mode tls-header
      --measurements <hex,...>`. The proxy injects `X-Attestation-Nonce`, verifies
      the `Attestation-Report` response header (signature + measurement allowlist +
      nonce binding), and fails closed (drops the response) on failure. See
      `internal/verifier/flow.go`.
- [x] Session-scoped re-attestation: a verified verdict is reused for up to one
      minute (`internal/verifier/cache.go`) so long-lived TLS sessions are not
      re-attested on every request — the TLS channel carries the guarantee between
      periodic freshness checks.
- [x] Trust custom upstream CAs and override the validated TLS name. Certs added
      with `certs add` are appended to the system roots and used as upstream trust
      anchors (`internal/proxy/proxy.go`, `Options.ExtraCAs`), and `remote add
      --server-name <name>` validates the upstream cert against `<name>` while
      still dialing the URL host — so a backend reached by raw IP whose cert only
      carries an internal DNS SAN (e.g. a c8s LB serving `c8s-tls-lb.c8s-system.svc`)
      now connects instead of failing `x509: ... doesn't contain any IP SANs`.
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
