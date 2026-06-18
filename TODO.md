- [x] Support TLS Header attestations (Flow A): `remote add --mode tls-header
      --measurements <hex,...>`. The proxy injects `X-Attestation-Nonce`, verifies
      the `Attestation-Report` response header (signature + measurement allowlist +
      nonce binding), and fails closed (drops the response) on failure. See
      `internal/verifier/flow.go`.
- [x] Flow A accepts both SNP nonce-binding shapes. Bare-metal SEV-SNP binds the
      nonce directly into the hardware `report_data`. Azure CVMs (`az-snp`) can't:
      the HCL fills `report_data` with `SHA-256(var_data)` (var_data carries the
      vTPM AK), so the nonce instead rides in an AK-signed TPM quote
      (`evidence.tpm_quote`). The `report_data → AK → quote → nonce` chain is
      verified by the shared `attestation-go` library (package `attestation/azsnp`,
      `Result.VerifyVTPMFreshness` — a Go port of attestation-rs `tpm_common.rs`),
      and `tlsHeaderVerifier` dispatches to whichever binding the evidence carries.
      One `tls-header` remote can therefore front a bare-metal or an Azure backend.
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
- [x] Converge TEE attestation verification on the shared `attestation-go`
      library. TEErminator no longer parses SNP/HCL/vTPM bytes itself: all of it
      lives in `attestation-go/attestation/azsnp` (the Go sibling of
      `attestation-rs`), and `internal/verifier` is a thin façade + freshness/
      measurement policy. TEErminator depends on it via a local `replace` directive
      (swap for a published version + `require` bump once tagged). The browser path
      still uses the `attestation-rs` WASM verifier; the Go and Rust verifiers now
      share the same `tpm_common` logic, so they agree byte-for-byte.
