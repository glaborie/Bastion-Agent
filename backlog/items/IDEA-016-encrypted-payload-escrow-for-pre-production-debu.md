### IDEA-016: Encrypted payload escrow for pre-production debugging, disabled in production

- status: done
- priority: P2
- phase: v0.3
- area: db
- tags: audit, escrow, encryption, debugging, forensics, pre-production
- depends-on: -
- spec: ADR-005
- created: 2026-11-11
- updated: 2026-11-12
- source: live incident on 2026-11-11, audit session f5c89000bc0c42499be2b2c87c13c78c (actor breakglass); the ledger and every service log retained no recoverable payload

**Problem**

Post-incident forensics cannot reconstruct what the model actually saw. In session `f5c89000bc0c42499be2b2c87c13c78c` the ledger kept a 27-character `payload_hash`, one `PERSON`, `restored_tokens: 1` and the routing verdict, while the delivered model text and the mangled DLP input existed nowhere — not in `audit_logs`, not in any service log — so the investigator had to ask the user to paste the transcript, and debugging the IDEA-014 false positive needed a live reproduction instead. This is by construction: `hash_payload()` (`db/models.py:155`) is one-way, `append_audit_event` (`db/audit.py:66`) accepts only a payload to hash or a precomputed digest, `metadata_json` is documented as never carrying raw PII, and `agent/tools/execution.py` states that argument values are never written to the ledger or to logs. ADR-005 decision 6 already permits encrypted raw-prompt storage "if the raw prompt must be stored (e.g., for debugging)", but nothing implements it, nothing bounds it, and `THREAT_MODEL.md:236` plus `audit_logs`' own schema still assert the hash-only posture.

**Outcome**

A pre-production-only escrow store keyed to the audit record can hold the exact payload behind a `payload_hash` as AES-256-GCM ciphertext, decryptable only by an authorised principal whose read is itself audited, while `payload_hash`, `record_hash` and every chain link stay byte-identical to today. The flag defaults off, production refuses to start with it on, and escrow rows expire on a shorter clock than the ledger without touching `audit_logs` or forking the chain.

**Acceptance**

- [x] `uv run pytest tests/test_payload_escrow.py -q` proves the flag off writes no escrow rows for a `POST /v1/chat` turn, and the flag on writes exactly one escrow row per escrowed event
- [x] The escrow row stores AES-256-GCM ciphertext with a per-record nonce, binds the audit record (`audit_logs.id` or `record_hash`) as AEAD associated data, and takes its master key from the environment/KMS by reusing or extending the vault's key handling in `agent/dlp/vault.py`; no key material is committed
- [x] A test dumps the escrow table and the captured logs for an escrowed turn and asserts no plaintext payload value appears in either
- [x] Decrypt round-trips: `hash_payload(decrypted_payload)` equals the row's `audit_logs.payload_hash`
- [x] `PAYLOAD_ESCROW_ENABLED=false` in `.env.example` with a comment that escrow is pre-production/debugging only; `ENVIRONMENT=production` with the flag `true` fails startup with an error naming `PAYLOAD_ESCROW_ENABLED`, proven with production-valid secrets so the dev-secret guard is not what raises
- [x] `uv run python scripts/verify_audit_chain.py` and `POST /api/audit/verify` stay green with escrow rows present, and a record's `payload_hash`/`record_hash` are identical with the flag on and off
- [x] Decrypt is reachable only through `require_roles`, requires an explicit principal action, and appends a new `AuditEventType` member carrying the record id, actor and outcome; a `readonly` or `analyst` principal is refused and no audit row claims a successful read
- [x] A purge job removes escrow rows past `expires_at` (the window a settings key, strictly shorter than the ledger retention in ADR-005 decision 5) without touching `audit_logs`, and the chain still verifies after a purge
- [x] `docs/adr/ADR-005.md` (or a successor ADR) records the escrow store, explicitly supersedes the "prompt text never enters the ledger" posture for it, states the new trust boundary and that production is excluded, and `uv run python scripts/check_adrs.py` passes
- [x] `.env.example`, `THREAT_MODEL.md` T10 and the `scripts/verify_audit_chain.py` runbook section (or `README.md`) give the exact enable/decrypt/purge commands and label the escrow table a PII store whose access needs review

**Notes**

- Decisions taken at promotion (2026-11-12), replacing the three "Open decision" notes: **(a) only the `input_raw` payload is escrowed**, on the `INPUT_RECEIVED` event. That is the only chat event whose `payload_hash` is the digest of user text (the later stages pass `{}`), so it is the only one that can satisfy both the decrypt round-trip and the "identical `payload_hash`/`record_hash` with the flag on and off" acceptance boxes without changing what is hashed. The post-DLP redacted text is reproducible offline from the raw input with the same DLP build, so it is not a second escrow kind; the delivered model text would need a new audit event and is deliberately out of scope. **(b) Expiry hard-deletes the escrow row and keeps no tombstone**: the ledger row (id, actor, event, `payload_hash`, `record_hash`) remains the evidence that the event happened, and a stub in a separate PII table would only add an index to data that is supposed to be gone. **(c) Access is the existing `admin` role only**, no new role and no four-eyes: ADR-005 decision 6 already names `admin`, a read is not a state change, and the tenant predicate plus the `ESCROW_ACCESSED` ledger row are the controls. The master key is a dedicated `PAYLOAD_ESCROW_MASTER_KEY` when set, otherwise HKDF-SHA256 of `VAULT_MASTER_KEY` under a fixed `info` label, so no new required secret and no committed key material.
- Classification: `P2`/`v0.3`. This is new capability, not a defect: no production guardrail is broken today and nothing leaked, so the next phase is the conservative home, and ADR-008 decision 5 freezes features inside a phase; no v0.2 line names payload escrow, while v0.3 already owns audit retention/export. `area: db` because the change lands as a table with an FK to `audit_logs.id`, an escrow writer beside `append_audit_event`, a purge job and the chain-verification invariant — the startup guard and the decrypt route are thin surfaces over that store. `security` was the alternative because the item also rewrites a stated invariant; not chosen because that content is ADR/THREAT_MODEL text in the same change rather than a cross-cutting code edit.
- Deduplication: no backlog item and no ADR mentions an escrow store, ciphertext payloads or payload recovery; the ADR hits for "payload" are the hash-only statements (`ADR-005` decision 1, `ADR-010` decision 8, `ADR-012` decision 4). IDEA-001 (tenant isolation) would have to cover the escrow table if it lands first — related, not a dependency, since escrow does not require tenant isolation to be built. IDEA-014 is the DLP bug this store would have made debuggable without a live repro, a different capability. IDEA-004 is ledger export/retention, not payload recovery; IDEA-009 is trace privacy; IDEA-015 is egress disclosure; done IDEA-006/008/011 are unrelated. `spec: ADR-005` because decision 6 already anticipates "encrypted at rest with KMS-managed keys and access-limited to `admin` role" for debugging, so this is covered by an ADR but not built, and the item amends that decision instead of inventing a second storage contract.
- The store cannot retroactively recover session `f5c89000bc0c42499be2b2c87c13c78c`; it only changes what the next investigation has. The retention window is deliberately shorter than the ledger's because this table is a PII store, and its access should be reviewed on the same cadence as the vault key.
- Scope at promotion: implemented in the change that promoted the item; the three decisions above are recorded in ADR-005 decision 7.
- Gates: `scripts/gate.sh --integration --evals` → 11/11, pytest 710 passed / 12 skipped, evals 232/232 with all metrics 1.000, pylint 10.00/10, mypy clean (78 files), all five policy scripts OK. The audit event CHECK constraint is widened idempotently on boot (`AUDIT_EVENT_VOCABULARY_DDL`) so an existing database accepts `ESCROW_ACCESSED`; `tests/test_settings.py` fails if the DDL and `AuditEventType` drift.
