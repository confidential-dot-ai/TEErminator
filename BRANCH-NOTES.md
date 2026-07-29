# `feat/cds-rollup` — branch notes

_Temporary. Delete before merge._

Base: `origin/main`. Two commits: `bb0f834` (RTMR[3] pin), `ab5b3ec` (attest CDS).

Independent of the other repos at build time — TEErminator deliberately does not
depend on the c8s module. It does depend on the **server** side of
`c8s@feat/cds-rollup` at runtime (`discovery.cds_identity`, config-claims v2/v3).

---

## The problem

`NewEndpointAttester` **required** a mesh CA pinned out of band —
`teerminator certs add mesh-ca.pem` — and failed closed without one. So "this
leaf was issued by the cluster" rested on a file someone sent you, and the whole
attestation chain hung off an anchor nothing verified.

---

## What changed

**`--expected-rtmr3`** (`bb0f834`) — pins the deployment, not just the build.
Bumps attestation-go `v0.0.0-20260618…` → `v0.4.1`.

**Attest CDS and derive the mesh CA** (`ab5b3ec`):

- `AttestCDSIdentity` verifies CDS's own RA-TLS certificate — quote, launch
  measurement, RTMR[3], and that REPORTDATA binds **both** its public key and its
  exact claims bytes.
- `VerifyMeshCA` accepts a served CA only on a digest match against those
  verified claims.
- `VerifyAllowlist` checks the raw `GET /allowlist` bytes against the attested
  live-allowlist digest.
- `teerminator certs derive <front-door-url>` wires all three into a command that
  replaces `certs add`.

The certificate is fetched from the front door's discovery document, **not** from
CDS, which is cluster-internal. Safe because it is self-authenticating: the
evidence binds its own key and claims, so a substituted or edited copy fails.
That is also why `--insecure-transport` cannot weaken the result — **no trust
decision rides on the transport**; the flag only allows bootstrapping from a
front door whose own chain is not yet trusted.

---

## The part to review carefully

Wire formats are **reimplemented**, not imported (no c8s module dependency). The
REPORTDATA transcript must stay byte-identical to
`ratls.ReportDataForKeyAndClaims`:

```
SHA-384( "c8s/config-claims/v1\0" ‖ framed(pubkey) ‖ framed(claims) ‖ framed(nonce) )
framed(x) = 8-byte big-endian length ‖ x
pubkey    = PKIX SubjectPublicKeyInfo DER
nonce     = EMPTY for a self-signed serving cert (c8s provider.go passes nil)
```

Get any of that wrong and everything fails closed — safe, but silently broken. A
fixture-only test would prove nothing; the live tests are the proof.

Two behaviours carried over deliberately from the endpoint attester: RTMR[3] is
checked off the signature-verified `rtmr_3` claim rather than passed as
`VerifyParams.ExpectedRTMRs` (go-tdx-guest numbers registers 1–4 and reports
RTMR[3] as *"RTMR[4]"*, which reads like a hardware fault instead of an identity
mismatch), and an RTMR pin on a non-TDX platform is an **error**, never a
silently dropped check.

---

## How this was tested

`go build ./...`, `go vet ./...`, `gofmt` clean, `go test ./...` green.

Live, against the bare-metal TDX cluster **over the public front door**:

```
certs derive --measurements <MRTD> --expected-rtmr3 <RTMR3>
  → Derived mesh CA "c8s Mesh CA" from a verified CDS attestation
    CDS launch digest 9309eaae…
    CDS cert SHA-256  48c57894…   ← the cache key; re-derive when it moves
    mesh CA digest    2aa039a5…  (attested)
    live allowlist    c96249d9…  (attested)
```

| wrong `--measurements` | exit **1**, nothing stored |
|---|---|
| wrong `--expected-rtmr3` | exit **1**, nothing stored |
| tampered certificate | rejected |
| allowlist with one extra byte | rejected |
| v1/v2 claims vs a v3 property | rejected as `not attested`, not silently zero |

Exit codes were checked directly, not through a pipe — `$?` after `| head` is
`head`'s status and reports 0 for a failing command. The trust store is confirmed
empty after a failed derive (no half-written state).

The live-fixture tests are env-gated and skip by default:
`TEERMINATOR_CDS_IDENTITY_PEM`, `TEERMINATOR_MESH_CA_PEM`,
`TEERMINATOR_ALLOWLIST_JSON`.

---

## What is missing / known-open

- **The proxy still consumes the CA from the config trust store.** `certs derive`
  writes it there, so the flow works, but nothing yet **re-derives** when CDS
  re-issues. The mesh CA regenerates on every CDS restart, so after one the
  stored anchor is stale until the operator re-runs `certs derive`. Worth
  automating: the CDS cert fingerprint is the signal.
- **No persistent attestation cache.** The verdict is recomputed per `derive`
  invocation. The design intends caching keyed on the CDS cert fingerprint;
  `config.Cert` is the natural home.
- **Downgrade** — replaying an old, internally consistent (cert, allowlist) pair
  is not blocked; only `notAfter` bounds it. Monotonic fingerprint tracking is
  designed, not implemented.
- `VerifyAllowlist` is exported but not yet called from the proxy path.
