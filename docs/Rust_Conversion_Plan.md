# Rust Conversion Plan (HCS-compatible target)

Status: plan only. Nothing here has been implemented, built or committed.
Written 2026-10-09 against commit `f524057` (master).

## Decisions already made

1. The target is HCS-compatible. HCS behaviour and its parameters are set in a TOML file (section 5).
2. The dependency list in section 10 (approved list) is approved, including `axum` + `tokio` as the async runtime. This is a design change: the Python endpoints are synchronous.
3. The conversion is a redesign by module, not a line-by-line translation.

## Evidence labels

* **[ran]** verified by running a command.
* **[read]** inferred by reading source. The code was not executed.
* **[spec]** taken from the Human Consent Standard draft at https://humanconsent.org/hcs (fetched 2026-10-07). The page describes itself as a Draft, so section numbers and wording may change.
* **[memory]** my recollection, not checked. Verify before relying on it.

---

## 1. Goals and non-goals

Goals

* G1. A Rust replacement for the `monitor/` service with parity for: certificate issuance and revocation, certificate status recorded on chain as UTXOs, the OCSP responder, the REST API, and the block monitor.
* G2. HCS certification PKI (HCS §3.3): issue signer certificates that satisfy the HCS JWS profile, and verify `<hcs:certification>` elements against a verifier-defined trust policy, including revocation status as of a past time.
* G3. Fix the carry-over hazards in section 9 instead of reproducing them.
* G4. Keep a legacy mode (`hcs.enabled = false`) so the Python and Rust services can be compared side by side before cutover.

Non-goals

* NG1. This is not an HCS Registry, Registration Authority or AI System. No HCRN/HCSI assignment, no declaration publishing, no sitemap or discovery, no conflict evaluation (HCS §3.1.9). HCS §6.2 says a valid certification "does not determine the current official Rights Declaration, establish Registry authorization, or affect whether the declaration is operative" [spec].
* NG2. The service never holds a signer's private key. Signing is a local CLI (`hcs-cli certify`).
* NG3. W3C DID and Verifiable Credentials are not in this plan (section 12).
* NG4. The `webserver/` demo (about 70 lines of FastAPI) is ported last, or left as the TLS test target.

---

## 2. What HCS requires of this project [spec]

Requirements come from HCS §3.3 unless noted. "Phase" says where the plan covers it.

| Requirement | Phase |
|---|---|
| JWS Compact Serialization with attached payload. Detached payload, JWS JSON Serialization and RFC 7797 unencoded payload MUST NOT be used. | 5 |
| `alg` MUST be `ES256`; verifiers MUST reject anything else. | 5 |
| Signature is the 64-octet fixed form R‖S (32-octet big-endian each), base64url, no padding. DER-encoded ECDSA signatures MUST NOT be used. | 5 |
| Protected header MUST contain `alg`, `cty` = `application/xml`, `x5c`. It MUST NOT contain `jwk`, `jku`, `x5u`, `b64`, `crit`; verifiers MUST reject a JWS that does. Verifiers MUST reject `cty` other than `application/xml`. Other header parameters are ignored. | 5 |
| `x5c`: each entry a base64-encoded DER certificate, signer first, then intermediates in chain order. A root MAY be included but that does not make it a trust anchor. | 5 |
| The signer certificate's public key MUST satisfy ES256 (RFC 7518 §3.4, which means P-256). | 6 |
| Payload = UTF-8 bytes of the exact `<hcs:right>` element as signed. It contains exactly one `<hcs:certification>` whose `jws` attribute is the empty string at signing time. No XML canonicalization; the signer chooses the serialization. | 5 |
| Verification (§3.3.2): validate the JWS; parse the payload as standalone XML with namespace processing; check exactly one certification with empty `jws`; check `registration-id` equals the enclosing published element's; check every certification attribute other than `jws` matches the payload. | 5 |
| Path validation (§3.3.3): RFC 5280 path validation at the certification `time`, under the verifier's trust policy "including any revocation requirements". The policy MUST define the trust anchors. Chaining to a public CA is not enough. `time` MUST NOT precede the payload's `issued` and MUST NOT be later than the time of verification. | 5 |
| XML handling (§8.1): disable external entity resolution, never fetch external DTDs/entities, reject any DOCTYPE, apply resource limits to XML parsing, JWS processing and certificate validation. | 5 |
| Timestamps (§2.1): RFC 3339 §5.6 date-time, uppercase `T`, uppercase `Z` when there is no numeric offset. | 1, 5 |
| `<hcs:certification>` attributes: `name`, `contact` (valid `https` or `mailto` URL), `time`, `jws` required; `role` optional lowercase token. | 5 |

HCS says nothing about how revocation is checked. That is left to the verifier's trust policy, and it is where UTXO-PKI plugs in.

---

## 3. Design decisions, with the flaw in each named

### 3.1 Role

Three things, none of which is an HCS Registry:

1. A CA that issues HCS signer certificates and records their status on chain.
2. A verifier (library, CLI and HTTP endpoint) for `<hcs:certification>` with a TOML trust policy.
3. A local signing CLI used by certifying entities with their own keys.

### 3.2 Key types

* HCS requires only the signer (leaf) certificate to be P-256. The CA key may use another curve [spec].
* Today: `monitor/src/vars` sets `EASYRSA_ALGO "ec"`, so the CA key is EC. The curve isn't set there; Easy-RSA's default is probably secp384r1 [read, memory]. Leaf and OCSP-responder keys come from `openssl genrsa` ([certificate_authority.py:106](../monitor/src/certificate_authority.py)), and the responder asserts `RSAPrivateKey` ([ocsp_responder.py:54](../monitor/src/ocsp_responder.py)) [read].
* In HCS mode the CA rejects any CSR whose SubjectPublicKeyInfo is not P-256. That check is the enforcement point; a config value alone isn't.
* Chain keys (secp256k1, used by `chain-gang` to sign transactions) and certificate keys (P-256, RSA) are separate config entries with separate key sources.

### 3.3 Revocation status and the `time` problem

Flaw. HCS requires the signer's path to be valid *at `time`*, but `time` is an attribute inside the signed payload and the signer chooses it. The only constraints are `issued ≤ time ≤ now`. A signer whose key was revoked yesterday can sign a new certification with `time` set to last week. A verifier that only compares `time` with the revocation timestamp accepts it.

"Valid at `time`" therefore means something only if one of these holds:

* (a) the revocation is treated as retroactive, or
* (b) the verifier has independent evidence that the certification existed before the revocation (section 3.5).

Retroactive-by-default would also reject legitimate certifications when a key is retired for a benign reason (for example re-keying). So both are TOML policy:

* `revocation_scope = "at-time"` is the spec wording and the default.
* `retroactive_reasons = ["keyCompromise", "cACompromise"]` makes those reason codes retroactive even in `at-time` scope. RFC 5280 does not say how to date a compromise. This default is my proposal for review.
* `timestamp_evidence.mode` selects (b).

Status evaluation for `revocation = "utxo"` uses the issue and spend transactions:

* The certificate's status output is Unspent, Spent (confirmed, with block time), Spent (unconfirmed), or NotFound.
* Block header time is set by the miner and only loosely accurate [memory]. `block_time_tolerance_seconds` widens the revoked window (fail-closed).
* An unconfirmed spend is treated as revoked with unknown time, so it is retroactive until confirmed (`unconfirmed_spend = "revoked"`).
* If the chain provider is unreachable the default is fail (`on_status_unavailable = "fail"`). HCS's "stays operative if unavailable" rule (§3.1.8) is about declaration revalidation, not certification, so it doesn't apply here. OCSP answers `tryLater` in that case.

The OCSP responder reports `revocationTime` as the spend's block time once confirmed. Today it is `datetime.now()` at the moment of revocation ([transaction_cache.py:173](../monitor/src/transaction_cache.py)) [read].

### 3.4 On-chain record

Today the locking script carries the full PEM and subject as JSON ([transaction_actions.py:181](../monitor/src/transaction_actions.py)) [read]. That is public and permanent. HCS §8.2 says declarations and records about natural persons may need to be erased [spec].

Payload v2 (HCS mode) carries only a version byte and `SHA-256(len(serial) as u8 ‖ serial ‖ SPKI DER)`, 32 raw bytes. `serial` is the minimal big-endian unsigned value (1 to 20 bytes, first byte non-zero), not the DER INTEGER bytes. The length prefix removes any ambiguity about where the serial ends and the SPKI begins. `SPKI DER` is the raw SubjectPublicKeyInfo slice as it appears in the certificate, copied verbatim from the CSR at issuance. The same definition is `Commitment` in [Plugin_Seam_Sketch.md](Plugin_Seam_Sketch.md). It does not commit to the certificate DER, because the certificate may carry its own status outpoint (`embed_status_outpoint`), and an outpoint that depends on the certificate hash is circular. The status output is created first; the certificate then embeds its outpoint.

* Legacy v1 payloads stay readable. `cert_id` is a JSON integer of up to 160 bits (X.509 allows 20 octets). It needs big-integer parsing (`serde_json` `arbitrary_precision`). New records never use JSON integers for serials.
* Open question OQ1: v2 layout. Option (a) keeps `<push> OP_DROP <P2PKH>`, the only layout the current UAAS collection flow is known to handle [read]. Option (b) is a plain P2PKH status output plus an OP_RETURN commitment in the same transaction, which is portable to BTC (BTC's relay policy rejects (a); [memory]). Default: (a) until OQ1 is answered.
* Encoding: the commitment is 32 raw bytes. Txids are stored in internal byte order; the usual hex display is the reverse [memory]. Conversion happens only at API boundaries, and phase 2 tests it with a known txid vector.

### 3.5 Optional extension: anchoring (not HCS)

Off by default. When on, the service writes a commitment to chain:

* `subject = "certification"`: `SHA-256` over the ASCII bytes of the JWS compact string. It provides independent existence-by-block-time evidence for the `time` problem in 3.3.
* `subject = "declaration"`: `SHA-256` over the exact published `<hcs:right>` bytes. It is evidence toward HCS §3.1.7.2, which asks whether an updated declaration was available no later than its `valid-from`. A hash on chain proves the content existed by the block time. It doesn't prove the content was published at the official location by then, so it supports the clause but does not satisfy it.
* HCS §4.3.3 lets the Registration Authority define audit receipts. A Merkle proof plus transaction is a candidate format, not a conformance requirement.
* Privacy: a bare hash of low-entropy content can be guessed. `salted = true` uses a random salt kept by the registry and delivered as a sidecar. Discarding the salt leaves nothing identifying on chain.
* Same-HCRN updates (HCS allows them) map to spending the previous tip output into a new tip. Withdrawal spends with no successor. Superseding spends with no successor and records the successor HCRN in an OP_RETURN. This is a design sketch only.

---

## 4. Architecture

Cargo workspace. Crate names are proposals.

| Crate | Contents |
|---|---|
| `utxo-pki-core` | Pure logic, no I/O: `Sats(u64)`, `Outpoint`, `Serial`, payload codec v1/v2, fee function, config structs and validation, `Clock` trait |
| `utxo-pki-chain` | `ChainClient` implementations (UAAS, WhatsOnChain, mock); transaction build/sign through `chain-gang` |
| `utxo-pki-ca` | `CertificateAuthority`: native P-256 issuance; an Easy-RSA adapter (`std::process::Command`) for legacy mode |
| `utxo-pki-ocsp` | OCSP request parsing and response building (RFC 6960) |
| `utxo-pki-hcs` | JWS profile, XML extraction, verification, trust policy, certify |
| `utxo-pki-store` | SQLite access |
| `utxo-pki-monitor` (bin) | `axum` service plus the block poller |
| `hcs-cli` (bin) | Offline `certify` and `verify` |
| `ocsp-requester` (bin) | Replaces the missing `monitor/src/tools/ocsp_requester.py`. `docs/OCSP.md` documents it, but the directory doesn't exist [ran: `ls monitor/src/tools`] |

Rules:

* **No globals.** The Python keeps `tx_cache`, `utxo_set`, `certificate_authority` and others as module-level singletons. Rust uses one `Arc<AppState>`.
* **Output state is three-valued.** `OutputState = Unspent{..} | Spent{spend_txid, confirmations} | NotFound`, with transport failures as `Err`. Today `get_tx_out_point` returns `{}` for spent, unknown and failed alike, and callers test `is not None`, which is never false ([transaction_actions.py:103](../monitor/src/transaction_actions.py), [rest_api.py:79](../monitor/src/rest_api.py)) [read].
* **Lock order.** The only lock is the single SQLite writer connection behind a `std::sync::Mutex`, used inside `spawn_blocking`. No other lock is held while taking it, so there is no ordering to get wrong.
* **Async traits.** Native `async fn` in traits is not object-safe [memory]. Use generics or enum dispatch, not the `async-trait` crate (not on the approved list).
* **Clock.** `SystemTime::now()` is a source of nondeterminism. It is used for OCSP `thisUpdate`/`nextUpdate`, observation times, and the `time ≤ now` check. All of it goes through an injected `Clock`.
* **Map ordering.** Use `BTreeMap` or SQL `ORDER BY` for anything listed or persisted, never `HashMap` iteration.
* **Poller.** A `tokio` interval every 15 s (as today), with `MissedTickBehavior::Delay` and a per-iteration timeout. If it stalls, status goes stale. `/health` exposes the last successful poll time. There are no unbounded queues; any channel is bounded.
* **Timeouts and retries.** Every outbound call has an explicit timeout; the Python `requests` calls have none [read]. A timeout maps to `ChainError::Timeout`, so OCSP answers `tryLater` and `verify` fails closed. Reads may retry up to 3 times with backoff inside a total request deadline. Writes are never rebuilt or retried (section 7, intents).

---

## 5. TOML configuration

### 5.1 New and changed sections

Sections not shown (`[web_interface]` aside from the additions below, `[uaas_interface]`, `[bsv_client]`, `[financing_service]`, `[ocsp_requester]`) carry over from `monitor/data/monitor.toml`.

```toml
# ---- HCS compatibility ---------------------------------------------------
[hcs]
enabled = true            # false = legacy behaviour (section 5.2)
profile = "1.0-draft"     # rule set; an unknown value is a startup error

[hcs.signer_certs]        # what this CA issues as an HCS signer certificate
key_algorithm   = "p256"  # only "p256" is accepted while hcs.enabled
validity_days   = 365
extended_key_usage = []   # HCS defines none; do not invent one
allow_server_side_keygen = false   # dev only; otherwise the service never sees signer private keys
embed_status_outpoint = false      # true requires status_extension_oid
# status_extension_oid = "1.3.6.1.4.1.<PEN>.1"   # no default; needs an allocated private enterprise number

[hcs.trust_policy]        # HCS 3.3.3: the verifier MUST define its anchors
anchors                = ["/etc/utxo-pki/anchors/ca.pem"]
revocation             = "utxo"      # "none" | "ocsp" | "utxo"
revocation_scope       = "at-time"   # "at-time" | "retroactive"
retroactive_reasons    = ["keyCompromise", "cACompromise"]   # RFC 5280 CRLReason names
on_status_unavailable  = "fail"      # "fail" | "soft-fail"
unconfirmed_spend      = "revoked"   # "revoked" | "ignore"
block_time_tolerance_seconds = 7200
min_confirmations      = 1
max_chain_depth        = 4
max_x5c_entries        = 8
max_jws_bytes          = 262144
max_xml_bytes          = 262144
max_clock_skew_seconds = 0           # tolerance on "time <= now"

[hcs.timestamp_evidence]  # NOT HCS: closes the self-asserted `time` gap (3.3)
mode = "off"              # "off" | "if-present" | "required"

[hcs.anchoring]           # NOT HCS: writes a commitment to chain (3.5)
enabled = false
subject = "certification" # "certification" | "declaration"
salted  = true

# ---- CA ------------------------------------------------------------------
[certificate_authority]
backend       = "native"   # "native" | "easyrsa" (legacy)
key_algorithm = "p256"     # CA key; HCS does not constrain it

# ---- Persistence (replaces [tx_cache_files] and the pickle files) --------
[store]
path = "/var/lib/utxo-pki/utxo-pki.sqlite3"
busy_timeout_ms = 5000

# ---- Value handling ------------------------------------------------------
[fees]
mode         = "payload-length"   # "payload-length" (parity) | "tx-size"
sats_per_kb  = 500
max_fee_sats = 10000              # refuse to broadcast if inputs - outputs exceeds this

[cert_wallets]
# Exactly one of *_file / *_env per key. Inline keys are rejected unless allow_inline_secrets = true (dev only).
funding_key_file     = "/run/secrets/funding_key"
certificate_key_file = "/run/secrets/certificate_key"
certificate_value    = 1000       # sats locked in each status output
default_p2pkh_fee    = 500        # sats

[ocsp_responder]
validity_seconds = 300            # nextUpdate = thisUpdate + this; today it is effectively zero

[web_interface]
address = "127.0.0.1:5003"
allow_non_loopback = false        # today APP_ENV=docker forces 0.0.0.0 and ignores the configured host
enable_debug = false
# admin_token_file = "/run/secrets/admin_token"   # see OQ4
```

### 5.2 Validation (startup fails with a message; nothing falls back silently)

1. Unknown keys are errors (`#[serde(deny_unknown_fields)]`). A typo in a security setting must not silently disable it.
2. `hcs.enabled = true` requires `hcs.signer_certs.key_algorithm = "p256"`.
3. `hcs.trust_policy.anchors` must be non-empty and every file must parse, whenever the verify endpoint or CLI is used.
4. `revocation != "none"` requires chain access (`bsv_client` / `uaas_interface`) or an OCSP URL.
5. `embed_status_outpoint = true` requires `status_extension_oid`.
6. All limits and durations are greater than zero; `max_fee_sats` is greater than `certificate_value + default_p2pkh_fee`.
7. `hcs.profile` must be a known value.
8. With `hcs.enabled = false`, `[hcs.*]` sections are ignored and a warning is logged.
9. Secrets never appear in `Debug` output or logs (`Debug` is implemented by hand for config structs).
10. `--config <path>` or `UTXO_PKI_CONFIG` is required. The Python loads `../data/monitor.toml` relative to the working directory and returns `{}` on a missing file ([util.py:35](../monitor/src/util.py)).

---

## 6. HTTP API

Existing endpoints keep their paths and JSON shapes in legacy mode, checked by golden tests from phase 0.

| Endpoint | Fate |
|---|---|
| `GET /`, `/issued`, `/revoked`, `/log`, `/cert_status`, `/cert_file`, `/ca_cert` | Kept |
| `GET /key_file` | **Removed.** It serves private keys with no authentication ([rest_api.py:176](../monitor/src/rest_api.py)) |
| `POST /create_cert` | Legacy mode only (server-side key generation). In HCS mode it returns 403 naming the config key |
| `POST /sign_csr` | Kept. In HCS mode it rejects non-P-256 CSRs |
| `POST /revoke_cert`, `/revoke_cert_file`, `/revoke_cert_by_serial_number` | Kept, rebuilt on the intent flow (section 7) |
| `POST /cert_file_status` | Kept |
| `POST /ocsp` | Kept |
| `POST /setup_ca` | Kept; the Easy-RSA adapter in legacy mode, native bootstrap otherwise |
| `POST /setup_blockchain` | **Removed.** The handler is a stub that returns "Not supported" |
| `POST /utxo test status` | Renamed `/debug/outpoint`, only when `enable_debug = true` (the path contains a space) |
| `POST /hcs/verify` (new) | Body: published `<hcs:right>` XML, optionally an anchor receipt. Returns a verdict with one result per HCS §3.3.2/§3.3.3 step |
| `GET /hcs/signer/{serial}/status?at=<RFC3339>` (new) | Status as of a time, with evidence: txids, Merkle proofs, block times |
| `GET /health` (new) | Last successful poll time, chain connectivity |

* Mutating endpoints have no authentication today [read]. See OQ4.
* Bind address: honour the configured address, and require `allow_non_loopback = true` for anything other than loopback.
* `hcs-cli certify` returns the JWS string and leaves placing it in the `jws` attribute to the caller. The signer chooses the exact serialization (§3.3.1), so the tool signs the bytes it was given and never re-serializes.

---

## 7. Data store

**Dialect: SQLite 3.** `STRICT` tables need 3.37 or later [memory]; `rusqlite`'s `bundled` feature ships its own SQLite, and phase 3 checks the version it carries. Postgres would differ (see the end of this section).

**Concurrency assumption.** One writer process (the monitor) with WAL journal mode. A second process, such as the importer or a CLI, must not write while the monitor runs. `busy_timeout` makes a stray writer wait and then error instead of hanging. `synchronous` stays at `FULL`: intents must be durable before a transaction is broadcast.

* **WAL (write-ahead log):** changes are appended to a log file before reaching the main database file. Readers don't block the writer, and each reader sees a snapshot from when its read began.
* **Isolation:** SQLite transactions are serializable. There is exactly one writer at a time. A transaction that will write begins with `BEGIN IMMEDIATE`, which takes the write lock up front, so a read-then-write sequence can't fail midway with `SQLITE_BUSY` on lock upgrade.
* **What breaks at weaker isolation:** the revoke logic reads status, decides, then writes. Under Postgres `READ COMMITTED` two concurrent revokes can both pass the read check. The primary key on `revocation` makes the second insert fail at any isolation level. The design depends on that constraint, not on the isolation level.

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;      -- off by default in SQLite; must be set on every connection

CREATE TABLE chain_tx (
  txid         BLOB    NOT NULL PRIMARY KEY CHECK (length(txid) = 32),   -- internal byte order
  block_hash   BLOB    CHECK (block_hash IS NULL OR length(block_hash) = 32),
  block_height INTEGER,
  block_time   INTEGER,          -- header time, unix seconds; miner-set, only loosely accurate
  merkle_proof BLOB              -- NULL until confirmed; serialization fixed in phase 2
) STRICT, WITHOUT ROWID;

CREATE TABLE certificate (
  serial       BLOB    NOT NULL PRIMARY KEY CHECK (length(serial) BETWEEN 1 AND 20),
  subject      TEXT    NOT NULL,
  key_alg      TEXT    NOT NULL CHECK (key_alg IN ('p256', 'rsa')),
  der          BLOB    NOT NULL,
  not_before   INTEGER NOT NULL,
  not_after    INTEGER NOT NULL,
  issue_txid   BLOB    NOT NULL REFERENCES chain_tx(txid),
  issue_vout   INTEGER NOT NULL CHECK (issue_vout >= 0),
  amount_sats  INTEGER NOT NULL CHECK (amount_sats >= 0),   -- integer base units, never a float
  UNIQUE (issue_txid, issue_vout)
) STRICT, WITHOUT ROWID;

CREATE TABLE revocation (
  serial       BLOB    NOT NULL PRIMARY KEY REFERENCES certificate(serial),
  spend_txid   BLOB    NOT NULL UNIQUE REFERENCES chain_tx(txid),
  reason       INTEGER NOT NULL CHECK (reason BETWEEN 0 AND 10 AND reason <> 7)  -- RFC 5280 CRLReason [memory]
) STRICT, WITHOUT ROWID;

CREATE TABLE intent (
  id         INTEGER PRIMARY KEY,         -- alias for the rowid
  kind       TEXT    NOT NULL CHECK (kind IN ('issue', 'revoke')),
  serial     BLOB    NOT NULL,
  state      TEXT    NOT NULL CHECK (state IN ('pending', 'broadcast', 'done', 'failed')),
  raw_tx     BLOB,                        -- stored once built, so a retry re-broadcasts identical bytes
  txid       BLOB,
  created_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX intent_live ON intent(serial, kind) WHERE state IN ('pending', 'broadcast');
```

Why it looks like this:

* **`STRICT`** makes SQLite enforce column types. By default it is dynamically typed, so an `INTEGER` column will happily hold text.
* **`WITHOUT ROWID`** stores the table as a B-tree keyed on the primary key. Normally SQLite keeps a hidden integer row id plus a separate index for your key. The OCSP hot path (`WHERE serial = ?`) should then be one B-tree descent.
* **The `UNIQUE (issue_txid, issue_vout)` index** is the one I expect the block scanner's "which certificate owns this spent outpoint?" lookup to use. Both index choices are my expectation (a guess), not read from a plan. Phase 3 confirms them with `EXPLAIN QUERY PLAN`.
* **Partial index `intent_live`** indexes only rows matching the `WHERE`. It allows at most one live intent per `(serial, kind)` while keeping finished ones as history.
* **Intent flow**, which fixes the chain-and-CA ordering problem (H6):
  1. Commit a `pending` intent.
  2. Build and sign, store `raw_tx`, broadcast, mark `broadcast`.
  3. Write the `certificate` or `revocation` row when confirmed, mark `done`.
  4. On restart, reconcile every `pending`/`broadcast` intent against the chain.
  5. Re-broadcasting identical bytes is safe. Rebuilding is not, because the funding service has already handed out the outpoints. A `broadcast` intent is never rebuilt.

**Migration (pickle files to SQLite)**

* This creates a new database. It rewrites no existing table and doesn't lock or modify the legacy `.dat` files.
* Reversible: delete the SQLite file.
* Step 1: a one-off Python exporter, using the original classes to unpickle `current_certs.dat` and `expired_certs.dat`, writes JSON lines. Rust never parses pickle.
* Step 2: `utxo-pki-monitor import` validates each record against the chain and inserts with `ON CONFLICT DO NOTHING` in one transaction. It is idempotent.
* In-flight writes: stop the monitor before exporting. If that isn't possible, re-run the import afterwards and reconcile against the chain.
* The legacy `revoke_time` is a naive `datetime.now()` in the container's TZ (`Europe/London` in the Dockerfile) [read]. The import records it as approximate; the spend transaction's block time is authoritative.

**If this ever moves to Postgres:** `BLOB` becomes `bytea`; `STRICT` and `WITHOUT ROWID` don't exist; the default isolation is `READ COMMITTED`; the `revocation` primary key still protects the revoke path.

---

## 8. Value and fee handling

* `Sats(u64)`. All arithmetic is checked and returns an error on overflow. There is no saturating or wrapping arithmetic in value paths. `#![deny(clippy::float_arithmetic)]` in `utxo-pki-core` and `utxo-pki-chain` (the lint is in clippy's restriction group [memory]; phase 1 confirms it fires).
* **Fee formula.** The Python is `int((payload_length / 1000) * 500)` ([transaction_actions.py:165](../monitor/src/transaction_actions.py)), a float in a value path. For payload lengths 0 to 199,999 it differs from the exact `len // 2` for 741 values, always 1 sat low, first at length 2002 [ran]. The Rust version is `len.checked_mul(sats_per_kb)?.div_ceil(1000)`.
  **This changes the fee**: up to +1 sat for odd lengths, and +1 more where the float undershoots. Flagged as an amount-computation change.
* **`calculate_fee` reads the module global `utxo_set`** instead of its `utxo` parameter (line 168) [read]. It disappears with the globals.
* **Fee basis.** The current formula uses payload length, not transaction size, and `default_p2pkh_fee` compensates. The code comment says transactions sometimes weren't mined [read]. `[fees] mode = "tx-size"` computes the fee from the serialized transaction. It is off by default because it changes amounts.
* **Change output.** The issuance transaction has exactly one output ([transaction_actions.py:206](../monitor/src/transaction_actions.py)). The funding request is `certificate_value + fee_estimate + default_p2pkh_fee`. Anything the funding service returns beyond the status output goes to miners [read; the funding service isn't in this repo, so its change behaviour is unverified]. The Rust version builds an explicit change output, or documents the funding service's exact-amount contract. This changes the output set and is flagged as such.
* **Fee guard.** Before broadcast, `fee = inputs - outputs` (checked) must not exceed `[fees] max_fee_sats`. Otherwise the intent fails and nothing is broadcast.
* `blockchain_setup.py:47` divides by `SATOSHIS` (float). It is dead code: its only call site is commented out and it imports `mopengine_dist`, which is not in `requirements.txt` [read]. It is not ported.

---

## 9. Carry-over hazards

Each of these is fixed in the Rust version rather than copied. All are [read] unless marked.

| # | Where | What | Fix |
|---|---|---|---|
| H1 | [transaction_actions.py:165](../monitor/src/transaction_actions.py) | Float fee, 1 sat low for some lengths [ran] | Section 8 |
| H2 | [transaction_actions.py:223](../monitor/src/transaction_actions.py), :233 | Prints the funding key as WIF | Keys from file/env, redacted `Debug`, no key material in logs |
| H3 | [transaction_actions.py:206](../monitor/src/transaction_actions.py) | No change output | Section 8 |
| H4 | [transaction_actions.py:103](../monitor/src/transaction_actions.py) | `{}` for spent, unknown and failed; callers test `is not None` | Three-state `OutputState` |
| H5 | [ocsp_responder.py:102](../monitor/src/ocsp_responder.py) | UNKNOWN is overwritten by GOOD (lines 102–105); `next_update` is a second `now()` call microseconds after `this_update` (lines 62–63); `assert cert == cert_validate` (:115) raises `AssertionError`, which `except ValueError` doesn't catch | Real `nextUpdate`, explicit errors, no `assert` on request paths |
| H6 | [rest_api.py:246](../monitor/src/rest_api.py) | Revoke spends the UTXO, then runs `easyrsa revoke`; create signs the cert, then broadcasts ([:213](../monitor/src/rest_api.py)). A failure between the two leaves the systems disagreeing | Intent flow (section 7) |
| H7 | [transaction_cache.py:183](../monitor/src/transaction_cache.py) | Pickle persistence; whole-file, non-atomic rewrite on every change | SQLite |
| H8 | [rest_api.py:176](../monitor/src/rest_api.py), [main.py:26](../monitor/src/main.py) | `/key_file` serves private keys; mutating endpoints are unauthenticated; the configured host is ignored | Section 6 |
| H9 | [certificate_authority.py:343](../monitor/src/certificate_authority.py) | Added in `f524057`: a bare `FastAPI(...)` call. `FastAPI` and `tags_metadata` are unbound in that module [ran: AST check]. I expect a `NameError` on import, so `main.py` shouldn't start at HEAD (not executed: dependencies aren't installed) | Not ported. Phase 0 uses a scratch worktree with these lines removed |
| H10 | [transaction_actions.py:181](../monitor/src/transaction_actions.py) | Serial stored as a JSON integer, up to 160 bits | Section 3.4 |
| H11 | Throughout | `requests` calls have no timeout | Section 4 |
| H12 | `monitor/run.sh` | Mounts `/var/run/docker.sock` into the container. I found no use of Docker in the source [read] | Dropped in the new image |
| H13 | [block_logic.py:30](../monitor/src/block_logic.py) | Merkle proofs are recorded for issuance only; `ExpiredCertificate.block_info` is never filled | Record the spend transaction's proof |
| H14 | [transaction_cache.py:173](../monitor/src/transaction_cache.py) | Revocation time is `now()`, reason is always `unspecified` | Block time from the spend; reason code recorded in the revoke transaction |
| H15 | `README.md`, `webserver/` | README says `https://localhost:5003`, but the monitor runs plain HTTP ([main.py:38](../monitor/src/main.py)) | Doc drift; fixed when the Rust service lands |

---

## 10. Dependencies

### Approved (2026-10-09)

| Crate | Why std or an in-tree option can't do it |
|---|---|
| `chain-gang` | Transaction building, signing, scripts. It is the Rust crate that the Python `tx-engine` wraps ([ran]: PyPI metadata, repository page), so behaviour matches what runs today. Nothing in-tree. |
| `rusqlite` (`bundled`) | No SQL engine in std |
| `serde`, `serde_json` (`arbitrary_precision`), `toml` | Config and payload parsing |
| `x509-cert`, `x509-ocsp`, `p256` (with `ecdsa`) | X.509, OCSP, ECDSA. I haven't checked current versions or APIs. |
| `rsa` | Legacy mode only, behind a cargo feature. The `rsa` crate had a timing side-channel advisory (RUSTSEC-2023-0071) [memory]; check `cargo audit` before enabling. |
| `axum`, `tokio` | HTTP server and async runtime (design change, approved) |
| `reqwest` (`rustls-tls`) | HTTP client. I took "an HTTP client" in the approved list to mean this. If it didn't, say so. |

### Needed for HCS, not yet approved

| Crate | Why |
|---|---|
| An XML parser (`roxmltree` or `quick-xml`) | Namespace processing; must reject DOCTYPE, resolve no external entities, and allow resource limits (HCS §8.1). Whether each rejects DTDs by default is **unverified**; phase 5 starts with a spike. |
| `base64` | Standard and URL-safe-no-pad alphabets; none in std |
| `sha2` | SHA-256 for ES256 and the commitments; none in std |
| `time` (with parsing) or `jiff` | RFC 3339 parsing and comparison; none in std |
| An RFC 5280 path-validation implementation | **Highest-risk choice.** It must accept an arbitrary validation time and a custom revocation check. Candidates: `rustls-webpki` (built for TLS server certificates, so its key-usage handling may not fit signer certificates), the `openssl` crate (FFI, links libssl), or a small restricted in-tree validator (security-critical code written by us). None chosen. Spike in phase 5. |

Deliberately not added: `async-trait`, `clap` (use `std::env::args` first), `tracing` (use a small logging shim first; ask if more is needed), `hex` (about ten lines in-tree).

---

## 11. Phases

No durations. Each phase has an exit criterion. The commands are what I intend to run; none has been run.

**0. Baseline and fixtures (no Rust).**
* In a scratch worktree at HEAD, remove `certificate_authority.py:343-347`. Do not commit that to master unless asked.
* Run the Python in its Docker image. Easy-RSA and `tx-engine` may not run on the macOS host.
* Add a small fake UAAS (HTTP stub) so the Python OCSP path can run without a chain.
* Capture: payload JSON for a known certificate; the fee for lengths 0 to 5000; OCSP DER responses for good, revoked and unknown; REST JSON for `/issued`, `/revoked`, `/cert_status`; unsigned transaction sighash preimages.
* Exit: fixtures committed under `tests/fixtures/` in the Rust workspace.

**1. `utxo-pki-core`.** `Sats`, fee function, payload v1 reader and v2 codec, config parse and validation (every rule in 5.2 has a test), `Clock`.
* Exit: `cargo test -p utxo-pki-core` and `cargo clippy --all-targets -- -D warnings` pass, with `float_arithmetic` denied. The fee function is compared with the exact integer reference over 0..=200,000, and overflow cases are tested.

**2. `utxo-pki-chain`.** `ChainClient`, UAAS and WoC clients, the mock, transaction build/sign via `chain-gang`, three-state output model, txid byte-order vector.
* Exit: the unsigned sighash preimages match phase 0. A testnet smoke run (manual; needs a funded key) issues and revokes one certificate.

**3. `utxo-pki-store`.** Schema, intent flow, importer, the Python exporter.
* Exit: round-trip import of a real `.dat` pair; `EXPLAIN QUERY PLAN` output attached for the OCSP lookup and the outpoint lookup.

**4. `utxo-pki-ocsp` and `ocsp-requester`.**
* Exit: `openssl ocsp ... -url http://localhost:5003/ocsp` (the command in `docs/OCSP.md` and the `rest_api.py` docstring) accepts the Rust responder's output. Status values match the phase 0 responses. Signatures and times will differ, so don't compare bytes.

**5. `utxo-pki-hcs`.**
* Spikes first: the XML parser, and the path-validation library (section 10).
* A negative-test matrix with one test per MUST in section 2: wrong `alg`; `jwk`, `jku`, `x5u`, `b64`, `crit` present; wrong `cty`; DER-encoded signature; padded base64url; detached payload; DOCTYPE; external entity; oversize input; mismatched `registration-id`; mismatched certification attributes; `time` before `issued`; `time` in the future; certificate not valid at `time`; unknown trust anchor; root in `x5c` not treated as an anchor.
* Positive tests: an ES256 JWS vector from RFC 7515 Appendix A.3 [memory]; a `certify` then `verify` round trip.
* An independent cross-check: verify a Rust-produced JWS with a separate implementation (Python `cryptography`, dev-only, not a dependency of the crates) and with `openssl`.
* Exit: every row of section 2 maps to a passing test.

**6. `utxo-pki-ca`.** Native P-256 signer-certificate issuance, CSR public-key check, the `hcs-signer` profile (`keyUsage = digitalSignature`, `CA:FALSE`), the Easy-RSA adapter for legacy mode. Revoke and issue go through the intent flow.
* Exit: a certificate issued here verifies in phase 5's `verify` and in `openssl verify`.

**7. `utxo-pki-monitor`.** HTTP API, poller, `/health`, multi-stage Docker image (the monitor image currently installs Rust and Python build tooling just to build `tx-engine`).
* Exit: golden API tests pass in legacy mode; HCS endpoints pass in HCS mode; the new image has no Docker socket mount.

**8. Shadow run and cutover.**
* Run Rust read-only beside the Python against the same chain. Compare OCSP status for every issued serial.
* Exit: no disagreements other than the hazards fixed in section 9. Python stays available for one release for rollback.

**9. Optional extensions.** Anchoring, per-HCRN status chain, DID/VC. Each is a separate decision.

---

## 12. Open questions

* **OQ1.** Payload v2 layout: `OP_DROP` script or OP_RETURN commitment (3.4). It depends on how the UAAS collection is populated, which isn't in this repo.
* **OQ2.** How does a third-party verifier (one with no access to this CA's database) find the spending transaction and its block time? If no provider endpoint returns the spender, as-of-time checks work only through evidence this service serves (spend txid, Merkle proof, block time), which the verifier then checks against block headers it trusts.
* **OQ3.** Defaults for `revocation_scope` and `retroactive_reasons` (3.3).
* **OQ4.** Authentication on mutating endpoints. This changes the API contract. My default: a bearer token (`admin_token_file`) required whenever the bind address isn't loopback.
* **OQ5.** The path-validation library (section 10).
* **OQ6.** Approval for the new HCS dependencies in section 10.
* **OQ7.** Whether `[fees] mode = "tx-size"` becomes the default after parity is proven.
* **OQ8.** CA curve: P-256 (one curve everywhere) or keep EC/P-384 for the CA key. HCS only constrains the signer certificate.
* **OQ9.** An allocated private enterprise number for `status_extension_oid`, if `embed_status_outpoint` is wanted.

### Deferred: DID and Verifiable Credentials

Not part of this plan. HCS's JWS profile forbids `jwk`, `jku` and `x5u` and requires `x5c`, so DID-based keys can't appear in `<hcs:certification>` without a new profile. HCS §6.1 leaves Registry authorization to the Governance Board's records. Once that format is finalized, a credential for registry authorization with a UTXO `credentialStatus`, or an age or guardian credential for the minors rule, are the candidate uses. W3C VC Data Model 2.0 and Bitstring Status List v1.0 are W3C Recommendations (May 2025); `did:btc1` is at W3C Credentials Community Group stage.

---

## References

* Human Consent Standard 1.0 draft: https://humanconsent.org/hcs (sections 2.1, 3.1.7, 3.1.8, 3.3, 4.3.3, 6.1, 6.2, 8.1, 8.2)
* `chain-gang`: https://github.com/nchain-innovation/chain-gang (PyPI package `tx-engine`)
* RFC 5280 (X.509 path validation), RFC 6960 (OCSP), RFC 7515 (JWS), RFC 7518 (JWA, ES256), RFC 3339 (timestamps)
