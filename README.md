# TEErminator
Localhost proxy for verifying and enforcing TEE-attestation from remote hosts through TLS-headers.

## Usage

TEErminator is a little daemon meant to allow anyone to connect to remote TEE APIs that are verified through attested TLS headers, or through dedicated session-scoped attestation.

In particular it is meant to support Confidential.ai stack and its confidential Kubernetes, C8s, which uses a ceritficate-backed attestation flow that abstracts away attestation verification form the end processes.

```
$ ./teerminator status
Local           Remote                                                  Auth        Status
127.0.0.1:8080  https://api.openai.com/v1/                              Token       Untrusted
127.0.0.1:14323 https://confidential-vllm-production-stack.lunal.dev/   None        Verified
127.0.2.1:443   https://api.baremetal.customer.com/                     mTLS        Verified
[::1]:8080      https://api.ollama.provider.com/v1/                     Token       Failed
```

Adding new remote TEE APIs:
```
$ ./teerminator remote add localhost:12345 https://example.com/v2/
$ cat SECRETTOKEN | ./teerminatore remote auth localhost:12345 -
```

Other supported commands include:

``` 
$ ./teerminator remote rm <common-name>
```

In particular it is meant to support Confidential.ai stack and its confidential Kubernetes, C8s, which uses a ceritficate-backed attestation flow tha     t abstracts away attestation verification form the end processes.
And the command `remote remove` or `remote rm` allows you to delete a remote.

For certificate-backed attestations, you might have to trust custom certificate authorities, especially when testing using localhost certs that might having been created using mkcert. Certificates added with `certs add` are appended to the system trust store and used as **upstream** TLS trust anchors for every remote, so a backend served by a private CA (e.g. a c8s mesh CA) verifies.

When the upstream's certificate does not match the host you dial — for example a LoadBalancer reached by **raw IP** whose cert only carries an internal DNS SAN like `c8s-tls-lb.c8s-system.svc` — pass `--server-name` on `remote add` to validate the certificate against that name (like `curl --resolve <name>:<port>:<ip>`); the connection still dials the URL host:

```
$ ./teerminator certs add ./mesh-ca.pem
$ ./teerminator remote add 127.0.0.1:8080 https://<LB-IP>/ \
    --mode tls-header --server-name c8s-tls-lb.c8s-system.svc --measurements <hex,...>
```

### Attestation modes

`--mode` selects how each remote is verified:

- **`tls-header` (Flow A)** — verify SEV-SNP evidence carried in an `Attestation-Report`
  response header, binding a fresh per-request nonce. Works for bare-metal SNP
  (`report_data == nonce`) and Azure az-snp (nonce in the AK-signed vTPM quote).
- **`attest` (Flow B)** — the same challenge/response attestation the `c8s-verify-js`
  browser client performs, against the LB's `/.well-known/c8s/attestation` endpoint, but
  riding the validated upstream TLS instead of the post-quantum tunnel. At session start
  TEErminator fetches a fresh, nonce-bound bundle (requesting the LB's **tls-cert binding**,
  `pq=false`), verifies the SEV-SNP evidence and that `report_data == SHA-384(serving_leaf_spki || nonce)`,
  checks the measurement allowlist, then **pins the verdict to that attested TLS leaf** —
  forwarded requests must ride a connection presenting the same leaf, otherwise the session
  re-attests (fail closed). This is a *TLS-session-scoped* TEE binding: the hardware report
  commits to the very certificate the traffic flows over. Requires a cluster whose `tls-lb`
  serves the tls-cert binding (`cds-attest --serving-cert-file`); az-snp is supported today
  (bare-metal snp Flow B is not yet wired — use the browser client).

```
# Flow B against an Azure node-as-CVM LB:
$ ./teerminator certs add ./mesh-ca.pem
$ ./teerminator remote add 127.0.0.1:8080 https://<LB-IP>/ \
    --mode attest --server-name c8s-tls-lb.c8s-system.svc --measurements <hex,...>
```
```
$ ./terminator certs add <CA PEM File>
$ ./terminator certs
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
$ ./terminator certs rm <common name>
```


