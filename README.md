# TEErminator
Localhost proxy for verifying and enforcing TEE-attestation from remote hosts through session-scoped attestation bound to the upstream TLS session.

## Usage

TEErminator is a little daemon meant to allow anyone to connect to remote TEE APIs that are verified through dedicated session-scoped attestation.

In particular it is meant to support the Confidential.ai stack and its confidential Kubernetes, C8s, which uses a certificate-backed attestation flow that abstracts away attestation verification from the end processes.

`status` checks every remote live, with the same trust construction the proxy
forwards over: `--mode attest-lb` remotes run the full attest-lb verification,
unattested remotes are probed for reachability, and modes the proxy cannot
enforce yet report `Failed`. Details (the verified measurement, workload name,
and trust mode, or the failure reason) are printed below the table, and results
are persisted so `remote ls` shows the last checked status.

```
$ ./teerminator status
Local            Remote                                                 Auth   Mode       Status
127.0.0.1:8080   https://api.openai.com/v1/                             Token  None       Untrusted
127.0.0.1:14323  https://confidential-vllm-production-stack.lunal.dev/  None   attest-lb  Verified
[::1]:8080       https://api.ollama.provider.com/v1/                    Token  None       Failed

127.0.0.1:14323: measurement 6d86eef8bfaea0f34a2a8dda5b8b0a97c9174a01d0a3546b930b16fceccb6d9e1e0d1cbc35e4a839e00e2b71c50ee2e2, workload api, trust deployment-class (ca-vouched)
```

Adding new remote TEE APIs:
```
$ ./teerminator remote add localhost:12345 https://example.com/v2/
$ cat SECRETTOKEN | ./teerminator remote auth localhost:12345 -
```

Remotes are deleted with `remote rm`, by local address or by the index printed by `remote ls`:

```
$ ./teerminator remote rm <local-addr|index>
```

For non-attested remotes served by a private CA (e.g. when testing with mkcert certificates), certificates added with `certs add` are appended to the system trust store and used as **upstream** TLS trust anchors. For `--mode attest-lb` remotes they play a different role: the mesh CA is derived from the hardware-committed attestation, so no CA file is needed to connect — a `certs add mesh-ca.pem` is an optional pin that upgrades the verdict from deployment-class to specific-cluster (see below).

When the upstream's certificate does not match the host you dial — for example a LoadBalancer reached by **raw IP** whose cert only carries an internal DNS SAN like `c8s-tls-lb.c8s-system.svc` — pass `--server-name` on `remote add` to validate the certificate against that name (like `curl --resolve <name>:<port>:<ip>`); the connection still dials the URL host:

```
$ ./teerminator remote add 127.0.0.1:8080 https://<LB-IP>/ \
    --mode attest-lb --server-name c8s-tls-lb.c8s-system.svc --measurements <hex,...>
```

When the remote URL host is a raw IP and `--server-name` is omitted, it defaults to `c8s-tls-lb.c8s-system.svc` (the standard c8s LB SAN) and `remote add` prints a note saying so. Pass `--server-name` explicitly — e.g. the IP itself, for a certificate that does carry an IP SAN — to override the default.

### Attestation modes

`--mode` selects how each remote is verified:

- **`attest-lb`** — the ordinary-TLS native-client protocol against the LB's
  `/.well-known/c8s/attest-lb` endpoint (the legacy `attest` spelling and the retired
  `?pq=false` query selector are gone; old configs are normalized automatically).
  After each new upstream TLS handshake, and before any application bytes flow,
  TEErminator fetches a fresh nonce-bound bundle and verifies, in order: the
  `c8s/attest-lb/v1` binding identifier and nonce echo; the hardware evidence over
  `report_data = SHA-384(LP(version) || LP(nonce) || LP(SHA-256(serving_leaf_DER)) ||
  LP(SHA-256(mesh_leaf_DER)) || LP(SHA-256(mesh_CA_DER)))`, recomputed from the **exact
  serving certificate observed on that very connection**; the mesh-leaf key's proof of
  possession over the same transcript; and that both the committed mesh leaf and the
  serving leaf chain to the committed mesh CA. The verdict is then **pinned to the exact
  serving-leaf DER** (not just its key): a substituted certificate — even one reusing the
  attested key — refuses the handshake and forces re-attestation.

  Key properties:
  - **Derived CA = deployment-class.** No mesh CA file is needed: the issuing mesh CA is
    committed inside the hardware evidence and derived from the response, yielding a
    *deployment-class* verdict ("an expected measured c8s front door under the policy I
    pinned"). Because of that, upstream TLS trust for this mode is deferred entirely to
    the attestation (the WebPKI check is replaced by a strictly stronger hardware
    binding); `certs add` roots are not required to connect.
  - **Pinned CA = specific-cluster.** Adding the cluster's mesh CA with `certs add`
    upgrades the verdict to *specific-cluster* when the committed CA byte-equals the pin
    ("that particular cluster, not a genuine clone").
  - **Measurements are mandatory.** An empty `--measurements` allowlist is a
    configuration error in this mode, never a permissive default — as is an entry that
    is not a launch digest, so `--measurements ""` cannot stand in for a policy.
    `--image-manifest` is the other way to pin the launch digest, and supplies it in
    full; the two flags are mutually exclusive.
  - **Workload pin.** `--workload <name>` requires the committed mesh leaf to carry a
    matched-workload stamp (OID `1.3.6.1.4.1.66378.1.5`) naming `<name>`;
    `--allowlist <file>` additionally requires the stamp's digest to equal the SHA-256 of
    the exact file bytes and the stamped name to resolve in the document. The stamp is
    CA-vouched (`ca-vouched` profile in the verdict) — the mesh CA signature, not the
    hardware evidence, vouches for it.
  - **Platform-complete pinning.** The `--measurements` allowlist pins the launch
    digest, which means different things per platform. On **Intel TDX** the launch
    digest (MRTD) measures only the TDVF firmware — the guest kernel and rootfs live in
    RTMR[1]/RTMR[2] — so a complete image policy is the MRTD+RTMR[1]+RTMR[2] tuple,
    pinned with `--image-manifest <file>` (a JSON build-artifact manifest with `mrtd`,
    `rtmr1`, `rtmr2`, each 96 lowercase hex chars; the same format c8s
    `pkg/runtimemeasure` reads). All three registers are compared byte-exactly against
    the verified claims — the launch digest against the manifest's own MRTD included — so
    the manifest replaces `--measurements` rather than widening it: a second allowlist
    could only admit an image the manifest does not describe, and setting both is a
    configuration error. `--expected-rtmr3 <hex>`
    optionally pins the runtime operator-key/workload chain on top. Because MRTD alone is
    not an image identity, a *deployment-class* TDX verdict without `--image-manifest` is
    a configuration error; with a specific-cluster CA pin it passes but the verdict
    carries a prominent MRTD-only warning. On **AMD SEV-SNP** the launch digest already
    covers the full image (with kernel-hashes: firmware, kernel, initrd, cmdline), so no
    extra register pin exists; `--min-tcb <bootloader,tee,snp,microcode>` adds a
    component-wise minimum TCB floor (an all-zero floor gates nothing and is treated as
    no floor), and debug-launched guests are always rejected.
    Cross-platform pins fail closed: a TDX pin (`--image-manifest`/`--expected-rtmr3`)
    against SNP evidence is a hard error naming the platform, as is `--min-tcb` against
    TDX evidence — never a silently ignored option. All three require
    `--mode attest-lb`: on any other mode nothing would read them.
  - **Requires `public_tls.mode=cds`.** The serving key must be TEE-held and mesh-chained;
    a WebPKI front door refuses the endpoint with `400 unsupported_front_door` and can
    only be used through the encrypted-tunnel `attest-pq` protocol (browser client).

  Evidence verification is delegated entirely to the shared
  [`attestation-go`](https://github.com/confidential-dot-ai/attestation-go) verifier
  (`teeverify`), so every platform it supports works here: bare-metal/GCP SNP (binding in
  `report_data`), Azure az-snp (binding in the AK-signed vTPM quote), and the TDX variants.
- **`cds-cert`** — planned CDS-cert pinning; configuring it today fails
  closed (requests are blocked before reaching the backend).

```
# attest-lb against a mesh-chained (public_tls.mode=cds) front door, deployment-class:
$ ./teerminator remote add 127.0.0.1:8080 https://<LB-IP>/ \
    --mode attest-lb --server-name c8s-tls-lb.c8s-system.svc \
    --measurements <hex,...> --workload api --allowlist ./allowlist.json

# TDX: pin the complete image tuple (MRTD+RTMR[1]+RTMR[2]) from the build's manifest.
$ ./teerminator remote add 127.0.0.1:8081 https://<LB-IP>/ \
    --mode attest-lb --image-manifest ./image-manifest.json

# SNP: add a minimum TCB floor on top of the launch-digest allowlist.
$ ./teerminator remote add 127.0.0.1:8082 https://<LB-IP>/ \
    --mode attest-lb --measurements <hex,...> --min-tcb 3,0,8,209

# Optional hardening: pin the mesh CA to upgrade the verdict to specific-cluster.
$ ./teerminator certs add ./mesh-ca.pem
```
```
$ ./teerminator certs add <CA PEM File>
$ ./teerminator certs
common name:
    Issued To:
        ...
    Issued By:
             ...
    Validity Period:
        Issued On: <issuance iso-date>
        Expires On: <expiry iso-date>
    PEM-Encoding:
        -----BEGIN CERTIFICATE-----
        ....
        -----END CERTIFICATE-----

other common name:
    ...
$ ./teerminator certs rm <common name>
```


