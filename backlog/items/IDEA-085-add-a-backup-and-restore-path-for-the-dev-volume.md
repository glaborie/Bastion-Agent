### IDEA-085: Add a backup and restore path for the dev volumes before destructive resets

- status: active
- priority: P2
- phase: v0.5
- area: infra
- tags: backup, restore, postgres, minio, keycloak, dev-experience
- depends-on: -
- spec: ADR-008
- created: 2026-11-19
- updated: 2026-11-20
- source: session 2026-11-19 ("shouldn't we have data backups we could restore?" before IDEA-076's clean-volume reset)

**Problem**

The dev stack keeps its durable demo state in named volumes — `pgdata` (audit
ledger, approvals, handoffs, conversation rows), `keycloak_data` (realm users
and sessions), `miniodata` (audit witness objects and their object lock),
`omniroute_data` and `vault-data` — and nothing in the tree can capture or
restore them. `docker compose down -v` is the only reset, `scripts/cleanup.sh`
only handles worktrees, and there is no snapshot first. `ADR-008` lists
backup/restore for v0.5 and `COMPLIANCE.md` states the ledger and witness
retention requirement, but no script produces, verifies or restores a snapshot,
so any destructive reset loses the ledger irreversibly. A developer who keeps a
`.env` backup but no data backup cannot recover; IDEA-076's clean-volume
acceptance run is exactly such a reset.

**Outcome**

One documented, gitignored backup path captures Postgres, the MinIO witness
bucket and the Keycloak realm into `artifacts/backups/<timestamp>/` with a
digest manifest, and a matching restore path loads them into a fresh stack. A
round trip on a throwaway Compose project proves row counts, witness objects and
the audit chain survive. This is a dev snapshot, not a WAL/continuous backup or
a production retention control.

**Acceptance**

- [ ] `make backup` writes `.artifacts/backups/<UTC timestamp>/` containing a `pg_dump` of the ledger schema, a mirror of `AUDIT_WITNESS_BUCKET`, and a Keycloak realm export; the directory is gitignored and a `manifest.json` records each file's SHA-256 and size without printing a credential
- [ ] `make restore BACKUP=<dir>` fails closed on a missing manifest or a digest mismatch, and refuses a non-empty target unless `FORCE=1` is passed
- [ ] On a throwaway Compose project: append an audit row and a witness object, `make backup`, `docker compose down -v`, `make restore`, then `scripts/verify_audit_chain.py --witness` passes and both items are present with the same hashes
- [ ] `make backup` against an uninitialised stack fails naming the missing service and leaves an existing backup untouched
- [ ] `README.md` / `docs/TROUBLESHOOTING.md` document the commands and the honest limit (point-in-time dev snapshot, no WAL, no encryption-at-rest guarantee beyond the volume), and `ADR-008`'s v0.5 entry links the delivered path
- [ ] `scripts/gate.sh` is green

**Notes**

- Dedupe: grepped `backlog/items/` and `docs/adr/` for `backup`, `restore`, `pg_dump`, `snapshot`. `IDEA-078` restores the PKI toolchain, not data; `IDEA-063` is worktree cleanup; `ADR-005` requires retention of the ledger and escrow but names no capture path; `ADR-008` lists backup/restore as planned v0.5 work.
- Boundary: this is dev continuity, not the production HA/backup posture. A real deployment needs WAL archiving, encrypted off-host storage and a tested restore SLA, which stays with the v0.5 production scope rather than this developer tool.
- The audit witness is the awkward half: MinIO object lock means a restore cannot simply overwrite a version, so the restore path must target a fresh bucket/volume and re-run `scripts/init_audit_witness.sh`, with the lock dates preserved in the manifest.
- Classification: `P2`/`v0.5`/`infra`. It blocks no current work, but IDEA-076's reset and every future schema experiment rely on it.
- Scope: intake only. No Makefile, script, compose or document edit is part of this capture.
