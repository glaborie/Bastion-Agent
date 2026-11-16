### IDEA-062: Connect the runtime as a non-owner INSERT-only database role

- status: done
- priority: P1
- phase: v0.3
- area: db
- tags: audit, postgres, roles, least-privilege
- depends-on: -
- spec: ADR-005
- created: 2026-11-16
- updated: 2026-11-16
- source: triage of IDEA-052 on 2026-11-16

**Problem**

`DATABASE_URL` is the compose `POSTGRES_USER` for `gateway`, `worker`, the seed script and
the test suite (`docker-compose.yml:23,208`, `.env.example:21,26`), so the runtime is the
bootstrap **superuser** and the owner of every table — `init_models` creates the schema at boot
as that same role (`db/session.py:156-186`, called from `gateway/main.py:73` and
`agent/runtime.py:107`). Three consequences, all verified against a throwaway
`postgres:16-alpine` on 2026-11-16:

- An owner cannot be bound by `REVOKE`: `REVOKE UPDATE, DELETE ON audit_logs FROM <owner>`
  succeeds and the owner still updates. A superuser is never checked at all.
- The `bastion.allow_audit_mutation` opt-out (`db/models.py:279-296`) is a placeholder GUC,
  which PostgreSQL never privilege-checks. `GRANT SET ON PARAMETER` and `REVOKE SET ... FROM
  PUBLIC, app` both succeed and `has_parameter_privilege()` flips to `false`, yet
  `set_config('bastion.allow_audit_mutation','on',...)` still returns `on`. Postgres 16 cannot
  express "this role may not set it", which is exactly why IDEA-052 acceptance 3 is stuck.
- A non-owner holding only `INSERT, SELECT` is refused at the privilege check *before* the
  trigger runs, so table privileges do bind once the role is not the owner.

`TRUNCATE audit_logs` is not defended at all today (the trigger is `BEFORE UPDATE OR DELETE`
only), so a compromised credential can empty the ledger with the trigger intact. ADR-005
decisions 9 and 10 and `THREAT_MODEL.md` T10 already record the missing INSERT-only database
role as an open residual; this item is that residual, and it is the prerequisite for IDEA-052's
escape-hatch half.

**Outcome**

The request-serving processes hold a role that owns nothing and can only read and append the
ledger. `UPDATE`, `DELETE`, `TRUNCATE` and DDL on `audit_logs` are refused by privilege, the
`bastion.allow_audit_mutation` opt-out no longer exists, and the owner credential is not present
in the gateway or worker environment.

**Acceptance**

- [x] `DATABASE_URL` for `gateway` and `worker` authenticates as a role with
  `rolsuper = false`, `rolcreaterole = false`, `rolcreatedb = false`, and
  `pg_get_userbyid(relowner) <> current_user` for `audit_logs` and every other table
- [x] Schema creation and migrations run under a separate owner credential that the
  request-serving processes never hold — a one-shot `migrate` service or the db image's
  `docker-entrypoint-initdb.d`, then table `GRANT`s to the app role; not a
  `DATABASE_ADMIN_URL` in the gateway/worker environment
- [x] As the runtime role, `UPDATE`, `DELETE`, `TRUNCATE` and `ALTER TABLE ... DISABLE TRIGGER`
  on `audit_logs` are refused, while `INSERT` and `SELECT` succeed; the non-audit tables keep
  the DML the application needs
- [x] The `bastion.allow_audit_mutation` opt-out is deleted from `db/models.py`, ADR-005
  decision 3, `DEMO.md:545` and `COMPLIANCE.md:191`; break-glass maintenance is documented as
  owner DDL and tested to require the owner DSN
- [x] `tests/` fixtures and `scripts/seed_demo_approval.py` keep working through an owner DSN,
  CI creates both roles, and `docker compose up` reaches healthy from an empty volume
- [x] ADR-005 decisions 3, 9 and 10 and `THREAT_MODEL.md` T10 drop the "INSERT-only database
  role remains open" residual (re-run `scripts/recalculate_dread.py`); `COMPLIANCE.md` and the
  gate follow-up in `THREAT_MODEL.md:340` are updated
- [x] `scripts/gate.sh` passes

**Notes**

- Verified evidence for the two negatives, so the implementer does not retry them:
  `CREATE ROLE app; GRANT SET ON PARAMETER "bastion.allow_audit_mutation" TO app;` then
  `REVOKE ... FROM PUBLIC, app` leaves `has_parameter_privilege(...) = false` and
  `set_config(...)` still returns `on`; and `REVOKE UPDATE ON t FROM <owner>` leaves the owner
  able to update. Only ownership and superuser status decide, which is why the split is the fix.
- The design choice with the most blast radius is where the owner credential lives. A one-shot
  `migrate` service (compose `depends_on: service_completed_successfully`) keeps it out of the
  long-running processes; an admin DSN in `gateway`/`worker` re-creates the same hole under a
  different name and should be rejected in review.
- The role needs `CONNECT` on the database and `USAGE` on the schema, and `SELECT` on the
  sequence `audit_logs_id_seq`; `nextval` requires `USAGE`, not ownership.
- Touches: `docker-compose.yml`, `.env.example`, `settings.py` (two URLs or a bootstrap
  section), `db/session.py` (`init_models` must not run as the app role), `tests/conftest.py`,
  `.github/workflows/ci.yml`, `vault/bootstrap.py:165` (it seeds `POSTGRES_USER`), and the
  `pki` overlay, which pins the same bootstrap user.
- Deduplication: IDEA-052 is the digest half of the same ledger gap (four-eyes keys outside the
  hash) and is independently landable; this item removes the escape hatch and the owner
  credential. IDEA-059 is about moving non-human identity off a human token and does not touch
  the database role. Nothing else owns role separation.
- Classification: `P1`/`v0.3`/`db`. No shipped invariant is *newly* broken — the residual is
  already recorded in ADR-005 and T10 — but IDEA-052 cannot meet its outcome without it and
  the ledger can currently be truncated, so it is not a later-phase cleanup.

- Implemented 2026-11-16. Git status of the verification: `scripts/gate.sh` 12/12; `tests/test_db_roles.py` (new), `test_audit_chain.py` and `test_audit_witness.py` 19 passed against PostgreSQL 16 with `TEST_DATABASE_APP_URL`; `python -m db.migrate` created the schema and role on a fresh database; `scripts/seed_demo_approval.py` created a ticket through the owner DSN.
- Compose check on a fresh project and empty volume: `db` healthy, `migrate` exit 0, `gateway` healthy, `worker` running, `redis`/`keycloak` healthy, `otel-collector` started. The gateway's environment showed `bastion_app` as the DSN user and no owner password. `llama-cpp` and `omniroute` were not started because no GGUF model is present in `models/` (the README's Prerequisites step), so those two were not exercised; the role/schema change does not touch them.
- The opt-in `pki` overlay could not be exercised: `config/pki/pg_hba.conf` and the certificate issuance script are not present in this checkout. The overlay now carries a `migrate` block with the same TLS env and certificate mount as the gateway, but a running pki stack still has to map the app role from its client certificate; that is IDEA-023/ADR-019 work, not part of this item.
