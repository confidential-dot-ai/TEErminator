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


