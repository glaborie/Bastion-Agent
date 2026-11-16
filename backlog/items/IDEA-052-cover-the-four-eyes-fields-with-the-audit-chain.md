### IDEA-052: Cover the four-eyes fields with the audit chain hash

- status: blocked
- blocked-by: acceptance criteria need clarification
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

**Notes**

- Blocked 2026-11-16 on acceptance 3. PostgreSQL 16 cannot express "the runtime role cannot set `bastion.allow_audit_mutation`" with `GRANT`/`REVOKE`: the name is a placeholder custom GUC, so `GRANT SET ON PARAMETER` succeeds but a non-superuser can still `SET` it (verified against a throwaway `postgres:16-alpine`: after `REVOKE SET ... FROM PUBLIC, app` the role still set it and `has_parameter_privilege` returned false), and `ALTER SYSTEM SET` rejects the unrecognised placeholder so it never becomes a registered parameter. The runtime also connects as the bootstrap `POSTGRES_USER` superuser, which bypasses any parameter or table privilege. What is missing is the INSERT-only, non-superuser runtime role that ADR-005 decisions 9/10 and `THREAT_MODEL.md` T10 already record as open, plus a migration owner distinct from the runtime (today `init_models` creates and alters the schema at gateway/worker startup as the runtime role). That changes `docker-compose.yml`, the `DATABASE_URL`/`.env` contract, CI and the test fixtures, and it is not captured as a ready item. Acceptance 1 additionally needs a versioned hash input so v1 rows keep verifying (IDEA-059 Notes), which is worth deciding in the same pass. Triage should either capture the runtime-role split first and re-scope this item to the metadata digest once it lands, or drop acceptance 3 and keep the hash-coverage half as its own item.
