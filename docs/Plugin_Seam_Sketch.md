# Plug-in Seam Sketch

Status: sketch, a companion to [Rust_Conversion_Plan.md](Rust_Conversion_Plan.md). Not an implementation.
Written 2026-10-09 against commit `f524057` plus the plan branch.

## Context

UTXO-PKI is a demonstration system with no production deployments. The aim here is a lightweight, simple, pluggable identity system, and this sketch marks the seams where pieces would be swapped. The runnable part is [sketch/seam.rs](sketch/seam.rs): std-only Rust that type-checks and carries a few behaviour tests, using in-memory toy backends.

Evidence labels: **[ran]** verified by running a command, **[read]** inferred from reading source, **[memory]** my recollection, not checked.

## Shape

```
  front-ends   REST    OCSP    CLI          (thin adapters over the core)
                  \     |     /
          core:  verify · issue · revoke · Policy · intent log · Clock
                  /     |     \
  plug-ins    Format  StatusSource/Sink  Signer
```

The OCSP responder becomes a front-end over `status()`, not a plug-in. `/hcs/verify` from the plan is another front-end.

## Contract (abridged from `sketch/seam.rs`)

```rust
struct Time(i64);                                   // unix seconds, UTC
struct TimeEstimate { at: Time, uncertainty_secs: u32 }
struct StatusRef { scheme: String, id: Vec<u8> }    // opaque to the core
struct Commitment([u8; 32]);                        // see "Commitment encoding"

enum Status { Good, Revoked { since: TimeEstimate, reason: Reason }, Unknown }
struct StatusAnswer { status: Status, evidence: Option<Evidence> }

// 1. Status: read and write are separate traits, so a verifier holds no write capability
trait StatusSource: Send + Sync {
    fn scheme(&self) -> &'static str;
    fn status(&self, r: &StatusRef, at: Time)
        -> impl Future<Output = Result<StatusAnswer, SourceError>> + Send;
    fn check_evidence(&self, r: &StatusRef, e: &Evidence) -> Result<Status, SourceError>; // offline re-check
}
trait StatusSink: Send + Sync {            // both calls MUST be idempotent
    fn register(&self, c: &Commitment) -> impl Future<Output = Result<StatusRef, SinkError>> + Send;
    fn revoke(&self, r: &StatusRef, why: Reason) -> impl Future<Output = Result<RevokeReceipt, SinkError>> + Send;
}

// 2. Format: sync and CPU-only. No network, no status lookups.
trait Format: Send + Sync {
    fn verify(&self, input: &[u8], ctx: &VerifyCtx<'_>) -> Result<Verified, FormatError>;
    fn commitment(&self, req: &IssueRequest) -> Result<Commitment, FormatError>;
    fn issue(&self, req: &IssueRequest, status: &StatusRef, signer: &dyn Signer) -> Result<Vec<u8>, FormatError>;
}
struct Verified { subject, key, validated_at: Time, asserted_at: Option<Time>,
                  payload: Option<Vec<u8>>, status_checks: Vec<StatusRef> }

// 3. Key source: a sign oracle; private key bytes never cross it
trait Signer: Send + Sync {
    fn alg(&self) -> Alg;
    fn public_key(&self) -> &PublicKey;
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError>;   // ES256: 64-byte r‖s, big-endian
}

// core
async fn verify<F: Format>(f, sources: &[AnySource], input, policy, ctx) -> Outcome;
fn revoked_as_of(since, reason, t, p) -> bool {
    retroactive(p, reason) || since.at.0.saturating_sub(i64::from(since.uncertainty_secs)) <= t.0
}
```

## Flows

**Verify**
1. `Format::verify` runs and returns `status_checks`.
2. The core routes each `StatusRef` to a source by `scheme`.
3. It asks for status as of `validated_at`.
4. It applies the policy.

**Issue**
1. `Format::commitment`
2. `StatusSink::register`
3. `Format::issue`

The core's intent log wraps all three, so a crash between steps is reconciled on restart. The commitment excludes the credential itself, so a credential that embeds its own status reference is not circular.

**Revoke:** `StatusSink::revoke`, under the same intent log.

## Commitment encoding

`Commitment = SHA-256( len(serial) as u8 ‖ serial ‖ SPKI DER )`, 32 raw bytes, no hex.

* `serial` is the certificate serial as the minimal big-endian unsigned value: 1 to 20 bytes, first byte non-zero. A format rejects an empty serial, a leading zero byte, or more than 20 bytes (X.509 serials are positive and at most 20 octets [memory]). It is the numeric value, not the DER INTEGER bytes, which may carry a sign byte.
* The one-byte length prefix removes any ambiguity about where the serial ends and the SPKI begins.
* `SPKI DER` is the raw SubjectPublicKeyInfo slice as it appears in the certificate. At issuance it is copied verbatim from the CSR. Verifiers hash that slice and never a re-serialization of the parsed key.
* SHA-256 is used because the plan already depends on `sha2` for ES256.

## Config shape

```toml
[identity]
format = "hcs-jws"                 # closed set compiled in: "x509-p256" | "hcs-jws"
default_status_scheme = "utxo"     # for formats that carry no status ref: ref = (scheme, serial)

[identity.signer.file]
key_file = "/run/secrets/signer.pem"

[identity.status]
sources = ["utxo", "list"]         # a StatusRef's scheme selects the source
sinks   = ["utxo"]                 # verifier-only deployments: sinks = []

[identity.status.utxo]             # today's [bsv_client] / [uaas_interface] / [cert_wallets]
[identity.status.list]
path = "..."
[identity.status.http]
base_url   = "https://..."
timeout_ms = 3000
```

Unknown keys are errors, as in the plan's TOML rules.

## Where today's code lands [read]

| Today | Lands in |
|---|---|
| `create_certificate_transaction` | UTXO `StatusSink::register` |
| `spend_certificate_transaction` | UTXO `StatusSink::revoke` |
| `get_tx_out_point` plus `tx_cache.cert_status` | UTXO `StatusSource::status` |
| Merkle-proof code in `block_logic` | UTXO evidence builder |
| Easy-RSA CA (`certificate_authority.py`) | `Format::issue` |
| `ocsp_responder.py` | a front-end over `status()` |

## What was verified

[ran]: `rustc --edition 2021 --test docs/sketch/seam.rs` compiles with no warnings or errors on `rustc 1.95.0`, and all 8 tests pass.

```bash
rustc --edition 2021 --test docs/sketch/seam.rs -o "${TMPDIR:-/tmp}/seam_test" && "${TMPDIR:-/tmp}/seam_test"
```

The tests cover:

* a revocation after `t` is not revoked at `t`, and equality fails closed
* uncertainty widens the window toward "revoked"
* the subtraction **saturates toward revoked** at `i64::MIN` (saturating is deliberate, not wrapping or erroring)
* `keyCompromise` is retroactive even in `AtTime` scope
* unavailable fails closed unless the policy says soft-fail
* a malformed answer never soft-fails
* an unknown scheme is rejected

Not verified: any real format, any real backend (the two sources are toys), the `http` wire contract (not defined yet), and async behaviour under a real executor (the tests poll with `Waker::noop()`).

## Flaws and open points

1. **Only toy sources exist.** UTXO is the real test, because `register` must be idempotent per commitment while funding outpoints are consumed. Build `list` and `utxo` first, then `http`, before freezing the traits.
2. **"Pluggable" here means a closed set chosen at startup.** Enum dispatch is used because native `async fn` in traits isn't `dyn`-compatible [memory], and `async-trait` is not on the approved dependency list. Third-party plug-ins would go through the `http` source, an out-of-process JSON mirror of `StatusAnswer`. That avoids dynamic loading, so no `unsafe`.
3. **`Signer` is sync.** A remote KMS would block a thread. Acceptable for a demo.
4. **The plan's `time` problem needs a capability the sketch lacks.** An optional `Anchor` trait would give existence-by-time receipts; only UTXO could implement it. Until then `timestamp_evidence` in the plan has no backing capability in this seam.
5. **Formats that carry no status ref** (plain X.509 without the embedded-outpoint extension) rely on `default_status_scheme`, with `ref = (scheme, serial)`.
6. **No key-resolution plug point.** X.509 and HCS carry keys in-band. A DID or VC format needs an extra resolver plug-in; add it only when such a format arrives.
7. **Status checks run sequentially.** The count is bounded by `max_chain_depth`.
8. **Policy defaults are proposals:** `retroactive_reasons = [keyCompromise]` and fail-closed on unavailable.
9. **Timeouts and retries:** each `StatusSource` implementation owns its timeout. `Unavailable` is the failure mode, and policy decides. The core never retries `register` or `revoke` itself; recovery is replaying the intent log, which relies on both calls being idempotent.
