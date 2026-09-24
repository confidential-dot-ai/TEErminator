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

Stored certificates are keyed by their SHA-256 fingerprint, not their subject: any number of CAs sharing a common name can be trusted at once (every c8s cluster's mesh CA is `CN=c8s Mesh CA`), so several clusters verify as specific-cluster concurrently. Only adding the exact same certificate twice is rejected.

When the upstream's certificate does not match the host you dial — for example a LoadBalancer reached by **raw IP** whose cert only carries an internal DNS SAN like `c8s-tls-lb.c8s-system.svc` — pass `--server-name` on `remote add` to validate the certificate against that name (like `curl --resolve <name>:<port>:<ip>`); the connection still dials the URL host:

```
$ ./teerminator remote add 127.0.0.1:8080 https://<LB-IP>/ \
    --mode attest-lb --server-name c8s-tls-lb.c8s-system.svc --measurements <hex,...>
```

When the remote URL host is a raw IP and `--server-name` is omitted, it defaults to `c8s-tls-lb.c8s-system.svc` (the standard c8s LB SAN) and `remote add` prints a note saying so. Pass `--server-name` explicitly — e.g. the IP itself, for a certificate that does carry an IP SAN — to override the default.

**In `acme` mode, set `--server-name` to the public hostname on the certificate** (e.g. `api.example.com`). A public ACME certificate carries the public domain in its SAN, never the raw-IP default or the internal c8s LB name, so leaving the default in place will always fail the name check.

#### ACME staging

A front door configured against the ACME **staging** directory (sensible while testing issuance) presents certificates that chain to staging roots no operating system trusts. Those roots still have to verify, so add the published staging root once — `certs add` roots are appended to the WebPKI pool used by the acme check, alongside the system roots:

```
$ ./teerminator certs add letsencrypt-staging-root.pem
```

The staging root provides chain trust for the acme check only. It is not a mesh-CA pin: the specific-cluster upgrade still requires the cluster's actual mesh CA.

### Attestation modes

`--mode` selects how each remote is verified:

- **`attest-lb`** — the ordinary-TLS native-client protocol against the LB's
  `/.well-known/c8s/attest-lb` endpoint (the legacy `attest` spelling and the retired
  `?pq=false` query selector are gone; old configs are normalized automatically).
  After each new upstream TLS handshake, and before any application bytes flow,
  TEErminator fetches a fresh nonce-bound bundle and verifies, in order: the
  `c8s/attest-lb/v1` binding identifier and nonce echo; the hardware evidence over
  `report_data = SHA-384(LP(version) || LP(front_door_mode) || LP(nonce) || LP(SHA-256(serving_leaf_DER)) ||
  LP(SHA-256(mesh_leaf_DER)) || LP(SHA-256(mesh_CA_DER)))`, recomputed from the **exact
  serving certificate observed on that very connection**; the mesh-leaf key's proof of
  possession over the same transcript; that the mesh leaf chains to the committed mesh
  CA; and that the serving leaf follows the attested mode's trust rule. In `cds` mode it
  chains to the mesh CA. In `acme` mode it passes WebPKI chain and hostname validation.
  The verdict is then **pinned to the exact
  serving-leaf DER** (not just its key): a substituted certificate — even one reusing the
  attested key — refuses the handshake and forces re-attestation.

  Key properties:
  - **Derived CA = deployment-class.** No mesh CA file is needed: the issuing mesh CA is
    committed inside the hardware evidence and derived from the response, yielding a
    *deployment-class* verdict ("an expected measured c8s front door under the policy I
    pinned"). In `cds` mode, attestation replaces WebPKI trust. In `acme` mode, WebPKI
    trust and the hardware binding are both required. `certs add` is not required for a
    certificate issued by a public CA.
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
    hardware evidence, vouches for it. `allowlist fetch` obtains that file from the
    cluster itself (see below); the stamp's allowlist **version** counter, which `status`
    prints for a workload-pinned remote, is a *claim* until you check the document behind
    it that way.
  - **Sealed policy.** `--static-allowlist` requires the committed mesh CA to be the one
    a c8s CDS running with `--static-allowlist` mints ([c8s#522](https://github.com/confidential-dot-ai/c8s/pull/522)):
    it must carry the static-allowlist stamp (OID `1.3.6.1.4.1.66378.1.3`, the SHA-256 of
    the one document that CDS enforces for its lifetime) and RA-TLS evidence (OID
    `…66378.1.1`) over its own public key. Because attest-lb already commits
    `SHA-256(mesh_CA_DER)` into the nonce-fresh `report_data`, both extensions are covered
    by per-handshake hardware evidence. TEErminator verifies the CA's embedded evidence
    through `attestation-go`, requires its launch to pass the same measurement policy as
    the front door (the `--measurements` allowlist or the `--image-manifest` tuple, plus
    `--min-tcb` when set), requires the sealed digest to equal the SHA-256 of the
    `--allowlist` file's exact bytes, and refuses a mesh leaf whose matched-workload stamp
    was decided under any other snapshot. This is what closes the gap the workload pin
    leaves open: with a dynamic allowlist the operator can widen the policy between two
    requests and have CDS stamp a new pod; with a seal, changing the policy means launching
    a new CDS and minting a new CA, which the next handshake refuses. Without `--allowlist`
    the seal is verified but compared to no reviewed document, and the verdict says so.
    `--init-data <hex>` additionally pins the sealed CA evidence's init-data claim (the
    SHA-256 of the CDS pod's kata init-data document) for pod-as-CVM deployments. Both
    require `--mode attest-lb`. On bare-metal SNP the CA certificate carries no VCEK, so
    the first verification fetches it from AMD KDS; the CA is immutable, so its verified
    claims are reused for later handshakes and only the policy is re-applied.
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
    optionally pins the runtime operator-key/workload chain on top, and *only* on top:
    RTMR[3] records events extended into a guest whose image the untrusted host selects,
    so it requires `--image-manifest` and is a configuration error without one. Because
    MRTD alone is
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
  - **Requires `public_tls.mode=cds` or `public_tls.mode=acme`.** The serving key must
    stay inside the TEE. A `cds` certificate chains to the mesh CA. An `acme`
    certificate chains to WebPKI and is also bound into fresh hardware evidence. A
    Kubernetes-supplied WebPKI key is host-visible, so attest-lb rejects that mode. It
    remains usable only through the encrypted `attest-pq` tunnel.

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

# Sealed policy: the mesh CA must seal exactly the reviewed allowlist, and the CDS that
# minted it must run on the pinned image.
$ ./teerminator remote add 127.0.0.1:8083 https://<LB-IP>/ \
    --mode attest-lb --image-manifest ./image-manifest.json \
    --static-allowlist --allowlist ./static-allowlist.json --workload api

# Optional hardening: pin the mesh CA to upgrade the verdict to specific-cluster.
$ ./teerminator certs add ./mesh-ca.pem
```

`status` reports a sealed remote as `sealed allowlist <digest> (mesh CA launch <digest>)`.
The digest is the same value `c8s allowlist digest <file>` prints, so a reviewer can pin
the document they read without contacting the cluster; `allowlist fetch --pin` is the
other way to obtain it, and under a seal the fetched bytes are also checked against the
sealed digest.

### Fetching the allowlist

`--allowlist <file>` needs a file. `allowlist fetch` gets it from the cluster instead of
having it couriered to you, and writes it only if the cluster's own attestation names it:

```
$ ./teerminator allowlist fetch 127.0.0.1:8080 -o ./allowlist.json --pin
Wrote 412 bytes to /home/me/allowlist.json
  workload api, allowlist version 7 (stamped), digest sha256:9f86d0…
  attested measurement 6d86eef8…, trust deployment-class (ca-vouched)
  This document is CA-vouched, not hardware-attested: the evidence binds the mesh leaf, the mesh CA vouches for the stamp in it, and the stamp names this digest.
Pinned /home/me/allowlist.json as the allowlist for 127.0.0.1:8080: every attest-lb handshake now requires the stamp to name this file's exact bytes.
```

The remote is attested exactly as `status` attests it (`--mode attest-lb` only, since no
other mode yields a stamp), the matched-workload stamp is read off the chain-verified mesh
leaf, `GET /allowlist` is fetched over a connection pinned to the attested serving leaf,
and the response is written only when SHA-256 over the bytes **as received** equals the
digest the stamp names and the stamped workload resolves in the document. The bytes go to
disk verbatim — the digest is over exactly them, so a JSON round trip that preserves the
document's meaning still produces a file the stamp no longer matches. A document that
fails the check is never written, not even partially, and the command exits non-zero.

**What this proves.** The hardware evidence binds the mesh leaf into the attest-lb
transcript; the mesh CA's signature over that leaf vouches for the matched-workload stamp
inside it; the stamp names the allowlist digest. The fetched document is therefore
**CA-vouched** — the snapshot the attested front door's workload match was decided under —
not hardware-committed, and not proof of what the cluster enforces right now. It is weaker
than an allowlist digest carried in hardware-committed config claims would be.

**A digest mismatch is ordinary.** The stamp names the snapshot the match was decided
under, so an allowlist edited between the leaf's issuance and your fetch legitimately
hashes differently. The command re-attests once by itself, because a freshly issued leaf
names the current snapshot; if it still mismatches, both digests are printed along with
the two version counters — the one on the stamp and the one the response's weak ETag
carries. Those counters only pick the wording: a *newer* served version reads as the
cluster moving on, while the *same* version claimed for different bytes cannot be churn
and is called out as such. The ETag is transport metadata outside the digest, so it never
decides the outcome.

An existing output file is never overwritten without `--force`, and when that file is the
remote's current `--allowlist` pin the refusal says so — replacing it changes the document
every later handshake is checked against. `--pin` stores the freshly written file as that
pin, which is the bootstrap this command exists for.

```
$ ./teerminator certs add <CA PEM File>
Added certificate "c8s Mesh CA" (fingerprint 9f86d081884c7d65)
$ ./teerminator certs
common name (9f86d081884c7d65):
    Fingerprint (SHA-256): <64 hex chars>
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

other common name (…):
    ...
$ ./teerminator certs rm <fingerprint|common name>
```

`certs rm` takes a fingerprint (full, or any unambiguous prefix) or a common name, and
removes exactly one certificate: a selector matching several — e.g. the shared
`c8s Mesh CA` name with more than one mesh CA stored — removes nothing and lists the
matching fingerprints to pick from.

### Pinning the rollout bound

A c8s router with `router.attest.pinnedAllowlist` adds a `cds_state` to every attest-lb
bundle: CDS's rollout state, bound to your nonce, signed by the mesh CA, and committed into
the transcript. Its `bound` lists every allowlist policy (`sha256:<hex>`) that may be
running. TEErminator verifies it on every attestation and reports the bound in `status`.

You choose how to trust it:

- **Follow the deployment.** Without pins the bound is verified and reported, not limited.
- **Pin reviewed policies.** With `remote add --pin-policy sha256:<hex>` (repeatable),
  attestation fails once the bound holds a policy you have not pinned, or when CDS runs
  without an activation lease. The error names the digest to review.

To review and pin the current bound, fetch every policy in it over the attested
connection. Each is written only when it hashes to its attested digest:

```
$ ./teerminator allowlist fetch 127.0.0.1:8080 --bound-dir ./policies --pin
```

When a router fences a connection opened before the bound widened, it answers 503. The
proxy then drops that connection and re-attests on the next request.

### Live config reload

The running daemon watches the config file: a `remote add`/`remote rm` or `certs add`/
`certs rm` from another terminal is picked up within a couple of seconds, starting or
stopping only the affected tunnels — no restart needed. Send `SIGHUP` to reload
immediately. A tunnel whose policy or trust store changed is restarted; an edit that
fails to apply (e.g. a port already taken) is logged and the daemon keeps serving the
rest.
