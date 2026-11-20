### IDEA-099: Decide whether readonly may list models

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, rbac, roles, client-compat
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-20
- source: session report on 2026-11-20 ("readonly is denied GET /v1/models")

**Problem**

`GET /v1/models` is gated by `MODEL_ROLES`, which `gateway/routers/openai_compat.py:75` sets to `CHAT_ROLES` (`gateway/auth/roles.py:42-46`), so `admin`, `operator` and `analyst` list the catalogue while a `readonly` principal is refused `403` before the handler. The route returns four alias names and reads nothing else: no ledger row, no tokens and no tenant data. Yet `readonly` is the role whose name means read-only access, `READ_ROLES` already includes it for every other read surface, and ADR-007 decision 9 calls it the pure viewer. ADR-026 decision 1 does record the current guard ("both routes require the same `CHAT_ROLES`"), but it records the coupling of the catalogue with chat rather than a reason the catalogue must stay hidden.

**Outcome**

The question is settled on the record: either `readonly` may call `GET /v1/models` and receives the same alias list as an analyst, or the refusal is confirmed with a reason that distinguishes catalogue metadata from a chat turn. In either case the role set for the route, ADR-026 decision 1 and the ADR-007 role matrix agree, and a test pins the per-role answer so a later refactor cannot change it silently.

**Acceptance**

- [ ] A parametrised test covers `GET /v1/models` for `admin`, `operator`, `analyst` and `readonly` and states the decided status for each (in `tests/test_openai_compat.py` or the `tests/test_dashboard_roles.py` matrix)
- [ ] If `readonly` is admitted: a `readonly` token gets `200` with the alias list and the request appends no audit row; if not, the reason is written in the ADR rather than left implicit
- [ ] `docs/adr/ADR-026.md` decision 1 (and ADR-007 decision 9 if the matrix gains the route) records the outcome, and `uv run pytest tests/test_openai_compat.py` plus `uv run python scripts/check_backlog.py --check` pass

**Notes**

- Dedupe: grepped `backlog/items/` and `docs/adr/` for `/v1/models`, `MODEL_ROLES`, "model catalogue", `readonly` and `read-only`. IDEA-060 built the route; IDEA-096, IDEA-094, IDEA-095, IDEA-092, IDEA-090 and IDEA-097 are other compat-surface findings; IDEA-068 and ADR-007 decision 9 define the dashboard role matrix but do not list this route. No duplicate.
- ADR-026 decision 1 currently mandates the denial, so this item is a decision-change question rather than an unrecorded gap: if the answer is to keep the refusal, the reason still has to be written down; if it is to admit `readonly`, that decision supersedes decision 1.
- Open for triage: whether `readonly` denotes read-only API access at all, or only read-only control-plane evidence. ADR-003 and ADR-007 define it as a viewer of the dashboard, audit, sessions, incidents, evals and approval list; the API semantics are not stated.
- Out of scope: RBAC-filtering the alias list per caller. `list_models` already returns all four aliases regardless of role despite its docstring, and ADR-026's consequence section leaves "any per-caller model-to-role policy" open.
