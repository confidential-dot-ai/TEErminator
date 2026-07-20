- [x] Live `status` command: every configured remote is checked at invocation
      time over the same upstream TLS trust the proxy uses
      (`internal/proxy/check.go`) — `attest` remotes run the full
      session attestation (Verified/Failed, with the measurement or failure
      reason printed below the table), unattested remotes are probed for
      reachability (Untrusted/Failed), unimplemented modes report Failed. The
      checked statuses are persisted so `remote ls` reflects the last check.
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
- [x] Support /attest remote endpoints: `remote add --mode attest`
      performs the session-start challenge/response against the LB's
      `/.well-known/c8s/attestation` endpoint (tls-cert binding, `pq=false`),
      verifies `report_data == SHA-384(serving_leaf_spki || nonce)`, and pins
      forwarded traffic to the attested TLS leaf (`internal/verifier/endpoint.go`,
      `internal/proxy/proxy.go`). Evidence verification is fully delegated to
      `attestation-go`'s `teeverify` dispatcher, so every platform it supports
      (snp, az-snp, tdx, az-tdx, gcp-snp, gcp-tdx) is accepted; TEErminator only
      computes the binding anchor and enforces the measurement allowlist.
- [ ] Support `/cds-cert` pinning. Config model (`Mode`, `Measurements`,
      `DiscoveryURL`, `Pin`) is in place; configuring the mode blocks every
      request before it reaches the backend (fail closed) rather than forwarding
      unverified. The cds-cert HTTP client + `remote pin` CLI are the remaining
      work. The browser client (`c8s-verify-js`) already implements the
      equivalent over the c8s LB `/.well-known/c8s/*` endpoints, so the wire
      contract is settled (see `c8s-verify-js/PROTOCOL.md`).
- [x] Converge TEE attestation verification on the shared `attestation-go`
      library. TEErminator no longer parses SNP/HCL/vTPM bytes itself: all of it
      lives in `attestation-go/attestation/azsnp` (the Go sibling of
      `attestation-rs`), and `internal/verifier` only adds session/freshness/
      measurement policy on top. The browser path still uses the `attestation-rs`
      WASM verifier; the Go and Rust verifiers share the same `tpm_common` logic,
      so they agree byte-for-byte.
