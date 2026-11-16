### IDEA-052: Cover the four-eyes fields with the audit chain hash

- status: done
- priority: P1
- phase: v0.3
- area: db
- tags: audit, ledger, four-eyes
- depends-on: -
- spec: ADR-005
- created: 2026-11-13
- updated: 2026-11-16
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`compute_record_hash` (`db/hashing.py:56-80`) covers
`id|timestamp|actor_id|event_type|payload_hash|previous_hash`. `approver_id`, `initiator_id`
and `outcome` live in `metadata_json` (`agent/tools/execution.py:621-628`,
`gateway/approvals.py:296-300`), outside the digest:

```json
"metadata_json": {"tool": ..., "outcome": "executed", "approver_id": "<sub>", ...}
```

An execution can therefore be re-attributed to a different approver, or `outcome: denied`
flipped, with no hash changing: `verify_audit_chain` still returns `ok` and the MinIO witness
agrees. T10 accepts a superuser attacker; it does not cover this narrower case where the ledger
cannot prove four eyes at all.

**Outcome**

Every field that proves four eyes is inside the digest, so re-attributing an approver or
flipping an outcome breaks verification — and rows written before the change keep verifying
unchanged.

**Acceptance**

- [x] `approver_id`, `initiator_id` and `outcome` are hash material for every new row: the
  record carries a `hash_version` and a `metadata_hash` (SHA-256 of the canonical
  `metadata_json` bytes, `canonical_payload_bytes`), and v2 rows hash those two fields under a
  `CHECK` that a v2 row has a 64-hex `metadata_hash` and a v1 row has none; v1 rows recompute
  with today's six fields, with no backfill
- [x] A test edits `metadata_json` on a v2 row and `verify_audit_chain` fails, while an
  untouched v1 row still verifies
- [x] The tenant-segment export carries `hash_version` and `metadata_hash` in each row and in
  `rows_sha256`, so `scripts/verify_audit_chain.py --segment` still verifies a v2 segment
  offline (`db/export.py:308-316` recomputes from the exported fields alone)
- [x] ADR-005 decision 2 (preimage) and decision 3 (boundary) record the versioned preimage and
  state that the GUC escape hatch, the owner credential and `TRUNCATE` belong to IDEA-062

**Notes**

- Triage 2026-11-16: acceptance 3 is moved to IDEA-062. Verified on `postgres:16-alpine`:
  `REVOKE SET ON PARAMETER "bastion.allow_audit_mutation" FROM PUBLIC, app` flips
  `has_parameter_privilege()` to `false` and `set_config(...)` still returns `on` (placeholder
  GUCs are never privilege-checked); `REVOKE UPDATE, DELETE ON audit_logs FROM <owner>` is a
  no-op; a non-owner with only `INSERT, SELECT` is refused before the trigger. The runtime role
  is the bootstrap superuser and table owner (`docker-compose.yml:23,208`, `db/session.py:156`),
  so no `GRANT`/`REVOKE` can satisfy "cannot set" until IDEA-062 lands. This half is independent
  of that split and closes the forgery path in the Problem section.
- Versioning is the irreversible part: `AuditLog.compute_hash` (`db/models.py:252-263`) and
  `verify_audit_chain` (`db/audit.py:197`) recompute the preimage from the stored fields, so
  changing it without `hash_version` makes every existing row fail. IDEA-059's notes record
  the same constraint for its `actor_type`/`agent_id` fields; whichever lands first decides the
  shape, and the other follows it.
- Cheapest build: one `hash_version SMALLINT NOT NULL DEFAULT 1` column plus one
  `metadata_hash CHAR(64)` column (NULL for v1), `compute_record_hash(..., version, metadata_hash)`
  branching on the version, `AuditLog.compute_hash` passing its own. `metadata_json` itself stays
  out of the digest so verification never depends on JSONB round-tripping: `metadata_hash` is
  SHA-256 over `canonical_payload_bytes(metadata_json)`, the same canonicalisation the payload
  and escrow already use.
- Re-scoring: `THREAT_MODEL.md` T10's narrow residual ("the ledger cannot prove four eyes") is
  addressed by this item; the credential-level residual stays with IDEA-062.
