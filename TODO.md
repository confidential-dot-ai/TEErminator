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
- [x] Migrate to the explicit `attest-lb` protocol: `remote add --mode attest-lb`
      (legacy `attest` configs normalized) runs the per-handshake verification
      against `/.well-known/c8s/attest-lb` — the old `/.well-known/c8s/attestation`
      `pq=false` selector is gone server-side (`400 invalid_request`). The
      evidence binds the fresh nonce and the exact serving-leaf DER observed on
      the connection together with the committed mesh leaf and issuing mesh CA
      (`report_data` LP transcript), the mesh-leaf key proves possession, both
      leaves must chain to the hardware-committed (derived) CA, and forwarded
      traffic is pinned to the exact attested leaf DER
      (`internal/verifier/endpoint.go`, `internal/proxy/proxy.go`). Evidence
      verification stays fully delegated to `attestation-go`'s `teeverify`.
- [x] Workload identity pins: `remote add --workload <name> --allowlist <file>`
      enforce the mesh leaf's matched-workload stamp (OID `…66378.1.5`, vendored
      strict parser in `internal/verifier/workloadext.go` with cross-repo golden
      vectors) and the pinned canonical-allowlist digest; verdicts report the
      workload, trust mode (deployment-class vs specific-cluster via an optional
      `certs add` mesh-CA pin), and the `ca-vouched` profile. An empty
      `--measurements` policy is now a configuration error in attest-lb mode.
- [x] Platform-complete measurement policy, generic across Intel TDX and AMD
      SEV-SNP. `remote add --image-manifest <file>` pins the TDX image tuple
      (MRTD joins the measurement allowlist, RTMR[1]/RTMR[2] compare exactly
      against the verified claims; vendored parser in
      `internal/verifier/imagemanifest.go` mirroring c8s `pkg/runtimemeasure`,
      kept honest by the shared `testdata/image_manifest.json` fixture),
      `--expected-rtmr3 <hex>` pins the runtime operator-key/workload chain, and
      `--min-tcb <bootloader,tee,snp,microcode>` enforces the SNP TCB floor
      (handed to attestation-go as `VerifyParams.MinTCB` plus a claim-side
      recheck; debug guests are engine-rejected). Cross-platform pins fail
      closed, a deployment-class TDX verdict without an image pin is a
      configuration error (specific-cluster warns instead), verdicts and
      `status` details report what was enforced, and the verdict-cache key
      covers the new pins (manifest file digest, RTMR[3], TCB floor).
- [ ] Superseded — do NOT merge: branches `feat/cds-rollup`,
      `feat/cds-identity-cache`, and `fix/derive-allowlist-and-binding` were
      built on the retired config-claims flow and are replaced by the attest-lb
      protocol above (config-claims retired server-side).
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
