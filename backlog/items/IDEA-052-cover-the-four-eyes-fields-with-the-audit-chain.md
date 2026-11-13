### IDEA-052: Cover the four-eyes fields with the audit chain hash

- status: inbox
- priority: P1
- phase: v0.3
- area: db
- tags: audit, ledger, four-eyes
- depends-on: -
- spec: ADR-005
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`compute_record_hash` (`db/models.py:229-239`) covers `id|timestamp|actor_id|event_type|payload_hash|previous_hash`.
`approver_id`, `initiator_id` and `outcome` live in `metadata_json`
(`agent/tools/execution.py:621-628`, `gateway/approvals.py:296-300`), outside the digest. The
append-only trigger's opt-out is a custom GUC (`db/models.py:344`), which PostgreSQL lets any role
set, and the application connects as `POSTGRES_USER` with no `GRANT`/`REVOKE` anywhere.

An execution can therefore be re-attributed to a different approver, or `outcome: denied` flipped,
with no hash changing: `verify_audit_chain` still returns `ok` and the MinIO witness agrees.
T10 accepts a superuser attacker; it does not cover this narrower case where the ledger cannot
prove four eyes at all.

**Outcome**

The fields that prove four eyes are inside the digest, and the mutation escape hatch is not
settable by the application role.

**Acceptance**

- [ ] The metadata keys used by the approval flow are part of the hash material, or moved to hashed columns
- [ ] A test shows that editing `metadata_json` makes verification fail
- [ ] The runtime database role cannot set `bastion.allow_audit_mutation` (explicit `GRANT`/`REVOKE`)
- [ ] ADR-005 decision 3 records the boundary
