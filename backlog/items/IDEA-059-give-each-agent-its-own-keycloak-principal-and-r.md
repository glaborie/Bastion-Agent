### IDEA-059: Give each agent its own Keycloak principal and registry entry

- status: inbox
- priority: P2
- phase: v0.4
- area: security
- tags: identity, rbac, keycloak, audit, rate-limiting
- depends-on: IDEA-054
- spec: -
- created: 2026-11-14
- updated: 2026-11-14
- source: session, design note on non-human principals against gateway/auth and db/audit.py, 2026-11-14

**Problem**

Every identity in the control plane is a human OIDC subject: `TokenValidator.validate_access_token` reads only `sub` (`gateway/auth/oidc.py:316-331`), `AuthContext.actor_id` calls that the stable audit identity (`gateway/auth/rbac.py:53`), the limiter keys on `ratelimit:<scope>:<principal_id>` (`gateway/rate_limit.py:127`), the vault session is derived from tenant plus actor, and `PendingApproval.initiator_id` (`db/models.py:422`) holds a human sub for the four-eyes comparison. The realm seeds no non-human client — `bastion-gateway` is the dashboard authorization-code client and `bastion-cli` is a public password-grant client, both with `serviceAccountsEnabled: false` (`config/keycloak/realm-export.json:68,120`) — so an automated caller either holds a human's token, sharing that human's budget and attributing its actions to them, or logs in as a human through `bastion-cli`. The ledger then has no field that says "agent X acting for Y", which is the first thing an auditor asks, and a human who owns three agents cannot have one suspended without suspending all of them. The four-eyes check is the sharp edge: `can_be_decided_by` (`db/models.py:510-512`) only requires the approver to differ from the initiator, so a human can approve their own agent.

**Outcome**

Each agent is a first-class principal rather than a borrowed human token. A per-agent confidential Keycloak client with a service account (`client_credentials`, short-lived access token; X.509 client auth through the existing `pki` overlay is the alternative to a shared secret) is registered in an agent registry row holding `agent_id`, `owner_sub`, tenant, status, expiry, allowed tools, allowed route aliases and a budget reference to the per-principal budget of IDEA-054. Effective tools are the global catalog intersected with the agent's role and its allowlist, so `docs/tools/v1.json` stays the outer gate and the allowlist only narrows it. Ledger rows and rate-limit/budget keys carry `actor_type`, `agent_id` and `owner_sub`, and a suspended registry row is denied at ingress, reusing the quarantine mechanism rather than adding a second switch. An agent token can never open a dashboard session.

**Acceptance**

- [ ] A `client_credentials` token is accepted on the API as an `actor_type=agent` principal while `GET /auth/login`, `GET /auth/callback` and every session-authenticated route refuse it, and the test asserts no `auth:session:*` key was written
- [ ] Setting the registry row to `suspended` makes the agent's next call fail at ingress with `403` and its visible ledger denial row, with no ARQ job enqueued (asserted against a real queue or a recording fake)
- [ ] Two agents with one owner have distinct `ratelimit:*` keys and distinct budgets: exhausting one returns `429` while the other's reservation still succeeds, in a test against live Redis with `REDIS_TEST_URL`
- [ ] A tool present in `docs/tools/v1.json` and satisfied by the agent's role but absent from its allowlist is refused, and a tool absent from the catalog is refused even when allowlisted, both covered by `tests/` cases
- [ ] `uv run python scripts/validate_rbac.py --strict` fails on an agent client with no registry row, on a registry `allowed_tools` entry missing from the catalog, and on an allowlisted tool whose `required_role` the agent's roles do not satisfy; it passes on the seeded realm
- [ ] `uv run python scripts/verify_audit_chain.py` exits `0` over a ledger mixing pre-change rows and post-change rows with `actor_type`/`agent_id`/`owner_sub`, and still exits `1` after a post-change row is edited
- [ ] A new ADR records the non-human principal and the four-eyes rule, `THREAT_MODEL.md` drops the "borrowed human token" residual and is re-scored with `scripts/recalculate_dread.py`, and `scripts/gate.sh` passes

**Notes**

- Deduplication: no existing item or ADR owns a non-human principal. The neighbouring items are different problems: IDEA-030 re-derives the identity already carried on a queued job, IDEA-052 covers the four-eyes columns in the audit hash, IDEA-054 (the budget reference above) prices inference per principal, IDEA-023 is transport mTLS, and IDEA-051 scopes the tool workspace to a tenant. ADR-003 and ADR-015 assume a human subject, so neither governs this.
- Classification: `P2`/`v0.4`/`security`. No shipped invariant is broken — the current path is attribution loss and shared budgets, not a leak — and ADR-008 freezes features inside a phase, so this is not `P0`/`P1`. `v0.4` is the nearest home because its scope names "dynamic RBAC"; `v0.3` (multi-tenancy, tenant-bound identity) and `v0.5` (production readiness, secrets and service identities) are fair alternatives for triage. `depends-on: IDEA-054` because acceptance prices the agent budget against the per-principal budget that item creates; the rest of the item is buildable without it if triage splits the budget reference out.
- Ledger versioning is the one irreversible part. `compute_record_hash` (`db/hashing.py:56-80`) hashes `id|timestamp|actor_id|event_type|payload_hash|previous_hash`, and `verify_audit_chain` recomputes that preimage for every row (`db/audit.py:197`), so adding fields to the preimage makes every existing row fail verification. The change needs a versioned hash input — the version carried on the row, v1 rows verified with the old preimage — and old rows must keep verifying, which is the acceptance box above.
- Four-eyes semantics, deliberately not decided: the conservative rule is that the approver must differ from both the agent and its `owner_sub`, which is stricter than today's `is_decidable`. Whether an owner may ever approve their own agent's mutating call, and whether a second agent may approve, is a decision for the ADR rather than this item's prose.
- Two smaller decisions left open: whether the registry lives in PostgreSQL beside `pending_approvals` or is derived from Keycloak client attributes with the row as a cache, and whether route aliases are checked in the gateway router or in the agent runtime. The suspend switch should reuse the quarantine store (both are "deny this identity now" with a TTL) rather than grow a parallel table.
