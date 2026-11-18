### IDEA-078: Restore the missing PKI toolchain and prove east-west TLS again

- status: inbox
- priority: P1
- phase: v0.5
- area: infra
- tags: tls, pki, docker, secrets
- depends-on: -
- spec: ADR-019
- created: 2026-11-18
- updated: 2026-11-18
- source: reading IDEA-040 before claiming it, 2026-11-18

**Problem**

The `pki` profile that ADR-019 records is not reproducible from the repository, because its toolchain has never been committed. `git ls-files | grep -i pki` returns only `docker-compose.pki.yml` and `docs/PKI.md`, and `git log --all -- scripts/pki config/pki` is empty, so these files have never existed on any branch: `scripts/pki/bootstrap.sh` (the first step `docs/PKI.md:12` tells an operator to run), `scripts/pki/{init-ca,issue-certs,check}.sh` (mounted at `/scripts` and executed as the `pki-init` and `pki-issue` commands), and `config/pki/pg_hba.conf` (mounted over Postgres's `hba_file`). The overlay also declares `secrets/ca_password` and `secrets/provisioner_password` as compose secret files that only the absent `bootstrap.sh` creates.

The consequences are not cosmetic. `docker compose -f docker-compose.yml -f docker-compose.pki.yml --profile pki up -d` cannot start on a clean clone: compose refuses a secret whose file is missing, and two volume mounts have no source. Even with those files created by hand there is no CA, so no leaf can be issued, and `curl --cacert pki/trust/ca.crt` or `psql sslmode=verify-full` has nothing to verify against. `README.md:1373` advertises `scripts/pki/check.sh` as the check that the CA key is untracked and owner-only, and that script does not exist. IDEA-023 is marked `done` and its implementation note lists `scripts/pki/{bootstrap,init-ca,issue-certs,check}.sh` as delivered, so the control is recorded as shipped while the tree cannot produce it — which is how IDEA-040 came to be blocked on a prerequisite that was believed to exist.

**Outcome**

The toolchain exists as tracked files and a clean clone can bring the profile up and prove the ADR-019 claims. `scripts/pki/bootstrap.sh` creates the two secret files (`0600`, gitignored) and the `pki/` tree; `init-ca.sh` initialises the CA once and leaves an existing `ca.json` untouched; `issue-certs.sh` generates each leaf from a local CSR with the documented lifetimes and owner-only keys, including the per-service SANs ADR-019 decision 3 requires; and `check.sh` asserts the CA key is untracked and owner-only and that leaves carry the expected SANs and validity. `docs/PKI.md`, `README.md` and `ADR-019` then quote commands that actually exist, and IDEA-023's implementation note names only files present in git.

**Acceptance**

- [ ] `git ls-files scripts/pki config/pki` lists `bootstrap.sh`, `init-ca.sh`, `issue-certs.sh`, `check.sh` and `pg_hba.conf`, and `scripts/pki/check.sh` exits `0` on a tree that has just run `scripts/pki/bootstrap.sh`
- [ ] On a clean clone with no `secrets/` or `pki/`, `./scripts/pki/bootstrap.sh` writes `secrets/ca_password` and `secrets/provisioner_password` with mode `0600`; a second run leaves their contents unchanged, and neither file is tracked (`git status --porcelain` stays clean)
- [ ] `docker compose -f docker-compose.yml -f docker-compose.pki.yml --profile pki up -d` starts: `pki-init` and `pki-issue` complete successfully and `db`, `redis` and `keycloak` report healthy
- [ ] The ADR-019 decision 4 pair reproduces verbatim: `psql "host=db port=5432 dbname=bastion user=bastion sslmode=verify-full sslrootcert=/pki/trust/ca.crt sslcert=/pki/gateway/tls.crt sslkey=/pki/gateway/tls.key" -tAc 'select 1'` returns `1`, and the same command without the client certificate fails with `connection requires a valid client certificate`
- [ ] The ADR-019 decision 5 pair reproduces: `redis-cli --tls --cacert /pki/trust/ca.crt --cert … --key … ping` returns `PONG`, and a plaintext `redis-cli -p 6379` connection fails
- [ ] `scripts/pki/check.sh` fails when the CA key becomes world-readable or is force-added to git, and passes again once restored — the check is proven by a deliberate break, not only by a green run
- [ ] `docs/PKI.md`, `README.md` and `docs/adr/ADR-019.md` reference only commands that exist, `IDEA-023`'s implementation Note names only tracked files, and `uv run python scripts/check_adrs.py` passes
- [ ] `scripts/gate.sh` stays green, including the `secret-material` step and the pki overlay render in the `infra` step

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `pki`, `mTLS`, `Step-CA`, `bootstrap`, `ca.crt`. The hits are IDEA-023 (done; the feature itself), IDEA-040 (blocked 2026-11-18 with this gap named in its Notes), IDEA-055 and IDEA-058 (image inventory, secret-material gate), and ADR-019/ADR-016. No item covers restoring the toolchain, so nothing was merged and no id was reused. This is the item IDEA-040's blocker points at.
- Classification: `P1`/`v0.5`/`infra`. Not `P0`: the default stack is plaintext by decision (ADR-019 decision 1), so no live guardrail is bypassed today and nothing leaks by default; what is broken is reproducibility of a control the repository, the README and the ADR all claim is shipped, and it blocks a v0.5 security item. `area: infra` because the work lands in `scripts/pki/`, `config/pki/`, `.gitignore` and the overlay; `security` is a fair alternative if triage reads it as the invariant rather than the files.
- Recover before rewriting: if the scripts still exist outside git — a shell history, an old checkout, a backup — restoring them and re-running the acceptance is cheaper and preserves whatever the original `check.sh` asserted. I found none in this repository's branches, worktrees or stashes, but I did not search the wider machine.
- Unknown scope, deliberately not guessed: what `check.sh` checked beyond "CA key untracked and owner-only" is recorded nowhere except `README.md:1373` and IDEA-023's note, so the implementer defines that scope and writes it down. Likewise the exact per-service SAN list for leaves other than `db`, `gateway` and `worker` should be derived from ADR-019 decision 3 rather than invented here.
- `.gitignore` already ignores `pki/` (generated material) and does not ignore `scripts/pki/`, so the intent to track the scripts is unambiguous; the capture changes no ignore rule.
- Intake only: no script, config, compose, document or ADR change is part of this capture, and the idea was not implemented in the turn that produced it.
