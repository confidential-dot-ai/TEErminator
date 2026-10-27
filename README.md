# TEErminator
Localhost proxy for verifying and enforcing TEE-attestation from remote hosts through session-scoped attestation bound to the upstream TLS session.

## Usage

TEErminator is a little daemon meant to allow anyone to connect to remote TEE APIs that are verified through dedicated session-scoped attestation.

In particular it is meant to support the Confidential.ai stack and its confidential Kubernetes, C8s, which uses a certificate-backed attestation flow that abstracts away attestation verification from the end processes.

`status` checks every remote live, with the same trust construction the proxy
forwards over: `--mode attest-lb` remotes run the full attest-lb verification,
unattested remotes are probed for reachability, and modes the proxy cannot
enforce yet report `Failed`. An attest-lb verdict that passed but leaves a property
unproven, such as a policy history nothing judged, reports `Partial` and names what is
not proven; the proxy still forwards to it, and logs `partial` and `not_proven` on
every attestation. Details (the verified measurement, workload name,
trust mode, route digest and how it was checked, or the failure reason) are printed below the table, and results
are persisted so `remote ls` shows the last checked status. `status` exits non-zero
when any remote is `Failed`, so scripts and CI can rely on its exit code.

```
$ ./teerminator status
Local            Remote                                                 Auth   Mode       Status
127.0.0.1:8080   https://api.openai.com/v1/                             Token  None       Untrusted
127.0.0.1:14323  https://confidential-vllm-production-stack.lunal.dev/  None   attest-lb  Verified
[::1]:8080       https://api.ollama.provider.com/v1/                    Token  None       Failed

127.0.0.1:14323: measurement 6d86eef8bfaea0f34a2a8dda5b8b0a97c9174a01d0a3546b930b16fceccb6d9e1e0d1cbc35e4a839e00e2b71c50ee2e2, workload api, trust deployment-class (ca-vouched), route digest 3f1c9a0b7d2e4c6f8a1b3d5e7f9a0c2e4b6d8f1a3c5e7b9d0f2a4c6e8b1de07a (operator-signed, revision 12)
```

Adding new remote TEE APIs:
```
$ ./teerminator remote add localhost:12345 https://example.com/v2/
$ cat SECRETTOKEN | ./teerminator remote auth localhost:12345 -
```

A remote can take its pins from a signed GitHub release instead of local files:

```
$ ./teerminator remote add 127.0.0.1:8080 https://api.confidential.ai/ --mode attest-lb \
    --release https://github.com/confidential-dot-ai/confidential-inference/releases/tag/v0.15.15 \
    --tdx-tcb-status UpToDate
```

`--release` downloads `release-bundle.json` and verifies it against
`release-bundle.sigstore.json` with the Sigstore public-good instance: the certificate
must come from a GitHub Actions workflow of that repository, run at that tag, and the
signature must be in the transparency log. It then downloads the assets the bundle names
(`allowlist`, and `operatorKey` when present), checks each SHA-256 against the bundle,
and stores the files under the config directory, in `releases/<owner>/<repo>/<tag>/`.
The bundle is the `--image-manifest`, the allowlist is the `--allowlist` (with the
front-door `--workload` derived from it), and the operator key is the `--operator-pkey`.
A release without an `operatorKey` leaves RTMR[3] and the routes unpinned unless you add
`--expected-rtmr3` or `--route-operator-key`.

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
  Before any application bytes flow, TEErminator fetches a fresh nonce-bound bundle
  and verifies, in order: the
  `c8s/attest-lb/v1` binding identifier and nonce echo; the hardware evidence over
  `report_data = SHA-384(LP(version) || LP(front_door_mode) || LP(nonce) || LP(SHA-256(serving_leaf_DER)) ||
  LP(SHA-256(mesh_leaf_DER)) || LP(SHA-256(mesh_CA_DER)) || LP(route_digest))`, recomputed from the **exact
  serving certificate observed on that very connection** and the bundle's `route_digest`
  (`LP(x)` is the 4-byte big-endian length of `x` followed by `x`); the mesh-leaf key's proof of
  possession over the same transcript; that the mesh leaf chains to the committed mesh
  CA; and that the serving leaf follows the attested mode's trust rule. In `cds` mode it
  chains to the mesh CA. In `acme` mode it passes WebPKI chain and hostname validation.
  The verdict is then **pinned to the exact
  serving-leaf DER** (not just its key): a substituted certificate — even one reusing the
  attested key — refuses the handshake and forces re-attestation. The daemon reuses a
  passing verdict for one minute, and never past the serving leaf's expiry: new upstream
  connections in that window are admitted only if they present the same leaf, and the
  first request after it re-attests. A failed attestation is kept for the same minute.

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
    the exact file bytes and the stamped name to resolve in the document. Without
    `--workload`, `remote add` pins the policy's front-door entry, the one entry named
    `c8s-router-<12 hex>` as the c8s chart seeds it, and fails when there is none or more
    than one. The stamp is
    CA-vouched (`ca-vouched` profile in the verdict) — the mesh CA signature, not the
    hardware evidence, vouches for it. `allowlist fetch` obtains that file from the
    cluster itself (see below); the stamp's allowlist **version** counter, which `status`
    prints for a workload-pinned remote, is a *claim* until you check the document behind
    it that way.
  - **Platform-complete pinning.** The `--measurements` allowlist pins the launch
    digest, which means different things per platform. On **Intel TDX** the launch
    digest (MRTD) measures only the TDVF firmware — the guest kernel and rootfs live in
    RTMR[1]/RTMR[2] — so a complete image policy is the MRTD+RTMR[1]+RTMR[2] tuple,
    pinned with `--image-manifest <file>` (a confos build manifest with `mrtd`,
    `rtmr1`, `rtmr2` under `tdx`, or a flat JSON object with the three, each 96
    lowercase hex chars; read by the attestation-go `runtimemeasure` loader `c8s verify` uses). All three registers are compared byte-exactly against
    the verified claims — the launch digest against the manifest's own MRTD included — so
    the manifest replaces `--measurements` rather than widening it: a second allowlist
    could only admit an image the manifest does not describe, and setting both is a
    configuration error. `--rtmr 1=<hex>,2=<hex>` (config key `rtmrs`) pins the
    kernel and rootfs registers by hand instead; they exclude `--image-manifest`, and
    both beside `--measurements` count as an image pin. RTMR[3] is pinned on top, and
    *only* on top: it records events extended into a guest whose image the untrusted
    host selects, so every spelling of it requires `--image-manifest`. Pin it as the
    operator key the guest initrd hashed, `--operator-pkey <pem-file>` (config key
    `operator_pubkey_path`; the seed is SHA-384(0x00*48 ‖ SHA-384(file bytes)), as
    `c8s verify --operator-pkey` derives it), or as the bare seed with
    `--expected-rtmr3 <hex>` or `--rtmr 3=<hex>`; name it once. A node that measures
    its allowlist policies extends RTMR[3] once per policy and lists them in its bundle
    (`measured_policies`); TEErminator accepts the quote when the longest prefix of that
    list that replays from the seed reaches the quoted register, and reports that prefix,
    the node's policy history, in `status`. A malformed list, or one longer than 256
    entries, fails closed. Without a seed pin a listed history is not replayed, and the
    verdict warns. See **Policy history** for how the history is judged. Because
    MRTD alone is
    not an image identity, a *deployment-class* TDX verdict without `--image-manifest` is
    a configuration error; with a specific-cluster CA pin it passes but the verdict
    carries a prominent MRTD-only warning. On **AMD SEV-SNP** the launch digest already
    covers the full image (with kernel-hashes: firmware, kernel, initrd, cmdline), so no
    extra register pin exists; `--min-tcb <bootloader,tee,snp,microcode>` adds a
    component-wise minimum TCB floor (an all-zero floor gates nothing and is treated as
    no floor), and debug-launched guests are always rejected.
    Cross-platform pins fail closed: a TDX pin
    (`--image-manifest`/`--rtmr`/`--expected-rtmr3`/`--operator-pkey`/`--tdx-tcb-status`) against SNP evidence is a
    hard error naming the platform, as is `--min-tcb` against TDX evidence — never a
    silently ignored option. Every pin in this list requires `--mode attest-lb`:
    on any other mode nothing would read them.
  - **Policy history.** A replayed history proves which allowlist policies the node
    enforced since boot, in order, not that any of them is acceptable. Choose how to
    judge them; the two ways exclude each other, and both need an RTMR[3] seed:

    | Flag (config key) | Accepts | Failure |
    |---|---|---|
    | `--pin-policy <sha256:hex or file>` (`pinned_policies`, repeatable) | Only these policies, for every history entry and for the policy the mesh leaf was issued under. A file is an allowlist document hashed exactly as read, the bytes `GET /allowlist` serves | `policy_history_not_pinned` |
    | `--trust-operator --trust-operator-key <pem-file>` (`trust_operator`, `trust_operator_keys`) | Every history entry, and the policy the mesh leaf was issued under, whose document CDS stores with an operator write token signed under these keys | `policy_history_unsigned` |

    Both fail with `policy_history_absent` when nothing replays: a node that does not
    measure its policies proves nothing about them. `--trust-operator` fetches each
    document from `/allowlist/objects/sha256/<hex>` at the front door, requires it to
    hash to its digest (`allowlist_digest_mismatch` otherwise), and checks the token at
    `<…>/signature` with the rules of c8s's `operatorauth.VerifyStored`: signature under
    one of the keys, `htm` PUT, `htu` `/allowlist`, `pbh` over the bytes, and an
    `exp`−`iat` window of at most five minutes. The bytes and the token authenticate
    themselves, so any replica may serve them; each attester remembers the digests it
    verified. Only a document uploaded whole with a signed `PUT /allowlist` carries a
    token, so a per-workload edit yields a policy this check refuses until a signed
    upload of the same document. The policy the mesh leaf was issued under is the one
    its matched-workload stamp names. That stamp is CA-vouched, so the verdict stays
    `Partial` unless the mesh CA is pinned (`certs add`, a specific-cluster verdict), and
    a leaf without a stamp leaves it `Partial` too. With neither check, a non-empty
    history is accepted and the verdict is `Partial`. `status` prints the check as
    `policy history pinned`, `operator-signed` or `unchecked`.
  - **Init data.** `--init-data <hex>` (config key `init_data_digest`) requires the
    evidence to commit exactly this SHA-256 of the init-data document: SNP `HOST_DATA`,
    TDX `MR_CONFIG_ID`, or vTPM PCR[8] on Azure.
  - **Sandbox ID.** `--sandbox-id <id>` (config key `sandbox_id`) requires the committed
    mesh leaf to carry this CRI pod sandbox ID (OID `1.3.6.1.4.1.66378.1.4`). Like the
    workload stamp it is CA-vouched. `status` prints the ID whenever the leaf carries one,
    and a malformed one fails the attestation even unpinned.
  - **Pins of `c8s verify` a remote does not take.** `--allow-debug`: debug guests are
    always rejected. `--served-policy-file`: it checks what a CDS target serves at
    `/measurements`, which an attest-lb front door does not answer. `--image-policy-file`:
    pin one image with `--image-manifest` and, for its anchor, `--operator-pkey`.
    `--fetch-allowlists` and `--expected-report-data` are not pins; `allowlist fetch`
    saves the document the leaf was issued under.
  - **TDX TCB status.** By default TDX evidence is verified offline: the quote signature
    and the PCK chain to the Intel root, with no TCB status. `--tdx-tcb-status <list>`
    names the Intel TCB statuses you accept, for example `UpToDate` or
    `UpToDate,SWHardeningNeeded`. With it, every attestation fetches the TCB info, QE
    identity and PCK CRLs from Intel PCS, refuses a revoked PCK chain, and requires the
    platform, TDX module and QE TCB levels to each carry an accepted status. Accepted
    values are `UpToDate`, `SWHardeningNeeded`, `ConfigurationNeeded`,
    `ConfigurationAndSWHardeningNeeded`, `OutOfDate` and `OutOfDateConfigurationNeeded`.
    An unreachable Intel PCS fails the attestation. `status` prints the least favourable
    matched status.
  - **Route digest.** The evidence binds `route_digest`, the SHA-256 of the route
    manifest the router had applied when it admitted the handshake. The bundle carries
    it as 64 lowercase hex characters; a bundle without it, or with any other form, is
    refused, and a forged value fails the transcript. `status` prints it and the proxy
    logs it on every attestation. `--route-digest <hex,...>` (config key
    `route_digests`) requires the attested digest to be one of the listed values, and
    the error names both. Take the value from `c8s routes digest FILE` or
    `c8s routes show`: it hashes the manifest bytes as stored on CDS, so hashing a
    reformatted copy or the signed envelope gives a digest that never matches. To
    change routes without failing, add the new digest to `route_digests` in the config
    file (the daemon reloads it; `remote add` sets pins only on a new remote), apply the
    new manifest, wait for every router replica, then remove the old digest. The digest is an admission-time snapshot: a manifest applied after the
    handshake routes later requests without new evidence until the next attestation.
  - **Route operator keys.** Instead of digests, `--route-operator-key <pem-file>`
    (repeatable; config key `route_operator_keys`, which stores the PEM keys themselves)
    pins the ECDSA public keys the operator signs route manifests with. With each
    attestation TEErminator fetches the manifest the router publishes at
    `/.well-known/c8s/routes`, alongside the handshake. Once the evidence verifies, it
    checks the manifest's write token under one of the keys and the manifest schema, and
    requires the manifest digest to equal the attested one. The router must run with
    route publication enabled. The publication can come from another router replica
    than the handshake, so on a digest mismatch it fetches once more on a new connection
    and accepts that manifest if its digest matches, even when the first fetch showed a
    newer signed revision; only the floor below refuses older revisions.
    Each tunnel keeps the last revision and digest it accepted in memory and refuses a
    lower revision, or the same revision with another digest. A lower revision, or a
    digest the re-fetch does not reconcile, usually means a replica that has not applied
    the newest manifest yet, so the tunnel attests once more on new connections before
    it fails. That repeats the whole verification, so such a failure takes up to twice
    as long to report. One attestation, retry included, shares a 60-second deadline, so
    a slow first attempt can leave no time for the retry. `status` (10 seconds by
    default) and `allowlist fetch` are also bounded by their own `--timeout`. The daemon forgets the floor on
    restart, and a tunnel forgets it when it restarts after an edit to its remote or to
    the trust store. `status` and `allowlist fetch` start each check at
    `--routes-floor`, or an empty floor without it, so they detect a rollback only below
    that configured floor.
    `--routes-floor <revision>:<digest>` (config key `route_floor`, requires
    `--route-operator-key`) starts that floor at a manifest you accepted before, so a
    restart does not forget it.
    The manifest must also route the remote URL's host, since the proxy sends it as
    `Host`, so the remote URL needs a DNS name the manifest routes, not an IP address.
    This check makes the remote depend on the publication: when it fails (404, any other
    error status, a digest no fetch reconciles, or a revision below the floor), the
    proxy refuses traffic for that remote until the re-attestation interval (one
    minute) has passed. Route changes on several replicas can cause such a window.
    `--route-digest` and `--route-operator-key` are mutually exclusive. With
    neither, `--operator-pkey` is also the route operator key when the remote URL has a
    DNS name: on a c8s server node the RTMR[3] launch key must equal the key the router
    verifies its manifest under, so one file pins both. Pass `--route-operator-key`
    when the router runs on a node launched with another key. With none of the three,
    `status` reports the digest as `unverified`.
    The field changes the attest-lb layout under the same `c8s/attest-lb/v1` binding
    identifier, so this version and a router that predates route-bound evidence do not
    interoperate in either direction.
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

# TDX: also require an Intel TCB status of UpToDate or SWHardeningNeeded.
$ ./teerminator remote add 127.0.0.1:8083 https://<LB-IP>/ \
    --mode attest-lb --image-manifest ./image-manifest.json \
    --tdx-tcb-status UpToDate,SWHardeningNeeded

# Pin the route manifest; list two digests while routes change.
$ ./teerminator remote add 127.0.0.1:8084 https://<LB-IP>/ \
    --mode attest-lb --measurements <hex,...> --route-digest <old-hex>,<new-hex>

# Or accept any route manifest the operator signed, published by the router.
$ ./teerminator remote add 127.0.0.1:8085 https://app.example/ \
    --mode attest-lb --measurements <hex,...> --route-operator-key ./operator.pub

# TDX: derive the RTMR[3] seed from the operator key and accept only these policies.
$ ./teerminator remote add 127.0.0.1:8086 https://<LB-IP>/ \
    --mode attest-lb --image-manifest ./image-manifest.json \
    --operator-pkey ./operator.pub --pin-policy ./allowlist.json,sha256:<hex>

# Or accept every policy the operator signed.
$ ./teerminator remote add 127.0.0.1:8087 https://<LB-IP>/ \
    --mode attest-lb --image-manifest ./image-manifest.json \
    --operator-pkey ./operator.pub --trust-operator --trust-operator-key ./operator-keys.pem

# Optional hardening: pin the mesh CA to upgrade the verdict to specific-cluster.
$ ./teerminator certs add ./mesh-ca.pem
```

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

### Live config reload

The running daemon watches the config file: a `remote add`/`remote rm` or `certs add`/
`certs rm` from another terminal is picked up within a couple of seconds, starting or
stopping only the affected tunnels — no restart needed. Send `SIGHUP` to reload
immediately. A tunnel whose policy or trust store changed is restarted; an edit that
fails to apply (e.g. a port already taken) is logged and the daemon keeps serving the
rest. The config file refuses unknown keys, so a misspelled pin such as `routeDigests`
fails the load instead of loading as unset; a reload that fails keeps the running
tunnels unchanged.
