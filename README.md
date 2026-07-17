# TEErminator
Localhost proxy for verifying and enforcing TEE-attestation from remote hosts through session-scoped attestation bound to the upstream TLS session.

## Usage

TEErminator is a little daemon meant to allow anyone to connect to remote TEE APIs that are verified through dedicated session-scoped attestation.

In particular it is meant to support the Confidential.ai stack and its confidential Kubernetes, C8s, which uses a certificate-backed attestation flow that abstracts away attestation verification from the end processes.

`status` checks every remote live, over the same upstream TLS trust the proxy
forwards over: `--mode attest` remotes run the full session attestation,
unattested remotes are probed for reachability, and modes the proxy cannot
enforce yet report `Failed`. Details (the verified measurement, or the failure
reason) are printed below the table, and results are persisted so `remote ls`
shows the last checked status.

```
$ ./teerminator status
Local            Remote                                                 Auth   Mode    Status
127.0.0.1:8080   https://api.openai.com/v1/                             Token  None    Untrusted
127.0.0.1:14323  https://confidential-vllm-production-stack.lunal.dev/  None   attest  Verified
[::1]:8080       https://api.ollama.provider.com/v1/                    Token  None    Failed

127.0.0.1:14323: measurement 6d86eef8bfaea0f34a2a8dda5b8b0a97c9174a01d0a3546b930b16fceccb6d9e1e0d1cbc35e4a839e00e2b71c50ee2e2
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

For certificate-backed attestations, you might have to trust custom certificate authorities, especially when testing using localhost certs that might having been created using mkcert. Certificates added with `certs add` are appended to the system trust store and used as **upstream** TLS trust anchors for every remote, so a backend served by a private CA (e.g. a c8s mesh CA) verifies.

When the upstream's certificate does not match the host you dial — for example a LoadBalancer reached by **raw IP** whose cert only carries an internal DNS SAN like `c8s-tls-lb.c8s-system.svc` — pass `--server-name` on `remote add` to validate the certificate against that name (like `curl --resolve <name>:<port>:<ip>`); the connection still dials the URL host:

```
$ ./teerminator certs add ./mesh-ca.pem
$ ./teerminator remote add 127.0.0.1:8080 https://<LB-IP>/ \
    --mode attest --server-name c8s-tls-lb.c8s-system.svc --measurements <hex,...>
```

### Attestation modes

`--mode` selects how each remote is verified:

- **`attest` (Flow B)** — the same challenge/response attestation the `c8s-verify-js`
  browser client performs, against the LB's `/.well-known/c8s/attestation` endpoint, but
  riding the validated upstream TLS instead of the post-quantum tunnel. At session start
  TEErminator fetches a fresh, nonce-bound bundle (requesting the LB's **tls-cert binding**,
  `pq=false`), verifies the SEV-SNP evidence and that `report_data == SHA-384(serving_leaf_spki || nonce)`,
  checks the measurement allowlist, then **pins the verdict to that attested TLS leaf** —
  forwarded requests must ride a connection presenting the same leaf, otherwise the session
  re-attests (fail closed). This is a *TLS-session-scoped* TEE binding: the hardware report
  commits to the very certificate the traffic flows over. Requires a cluster whose `tls-lb`
  serves the tls-cert binding (`cds-attest --serving-cert-file`). Evidence verification is
  delegated entirely to the shared [`attestation-go`](https://github.com/confidential-dot-ai/attestation-go)
  verifier (`teeverify`), so every platform it supports works here: bare-metal/GCP SNP
  (binding in `report_data`), Azure az-snp (binding in the AK-signed vTPM quote), and the
  TDX variants.
- **`cds-cert` (Flow C)** — planned CDS-cert pinning flow; configuring it today fails
  closed (requests are blocked before reaching the backend).

```
# Flow B against an Azure node-as-CVM LB:
$ ./teerminator certs add ./mesh-ca.pem
$ ./teerminator remote add 127.0.0.1:8080 https://<LB-IP>/ \
    --mode attest --server-name c8s-tls-lb.c8s-system.svc --measurements <hex,...>
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


