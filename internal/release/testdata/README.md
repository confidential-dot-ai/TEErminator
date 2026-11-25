Release assets of confidential-dot-ai/confidential-kubernetes, unmodified:

```sh
gh release download v0.108.0 --repo confidential-dot-ai/confidential-kubernetes \
  --pattern 'release-statement*' --pattern allowlist-seed-tdx.json --dir v0.108.0
gh release download v0.100.0 --repo confidential-dot-ai/confidential-kubernetes \
  --pattern 'release-statement*' --dir v0.100.0
```

v0.100.0 predates allowlist seeds and was signed as `confidential-dot-ai/C8s`.
`trusted_root.json` is the Sigstore public-good trusted root that cosign 3.1.4
cached from its TUF repository, at
`~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json`.
