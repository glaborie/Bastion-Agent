### IDEA-012: Add a dashboard demo console that runs the demo scenarios

- status: done
- priority: P2
- phase: v0.3
- area: gateway
- tags: dashboard, demo, htmx, rbac, arq
- depends-on: -
- spec: ADR-007
- created: 2026-11-10
- updated: 2026-11-11
- source: session request on 2026-11-10 ("improve the dashboard, cover more demo scenarios, run scripts")

**Problem**

`DEMO.md` is nine acts of copy-paste: Act 3 alone needs a `token_for` helper, two tokens, `ALICE_SUB`/`CAROL_SUB`, a ticket and a session variable, seven curl/script calls and a `docker compose exec` that edits the worker's tool catalog, and a stale token turns any of them into a 401 mid-demo. The dashboard stops at `/dashboard`, `/dashboard/audit`, `/dashboard/sessions/{id}` and `/dashboard/chat` (`gateway/dashboard/routes.py`), and the chat footer (`templates/chat.html` line 68) sends the presenter out of the browser to run `scripts/demo_egress.py` by hand. No page lists the demo entry points — `demo_classifier.py`, `demo_egress.py`, `demo_model_canary.py`, `demo_tool_request.py`, `demo_traffic.py`, `seed_demo_approval.py` — so a reviewer cannot see which controls are demonstrable or re-run one without the shell history.

**Outcome**

One dashboard page lists every demo scenario with the control it exercises and the evidence it should produce, and starts an allow-listed scenario on demand, showing the result and linking to the ledger or trace it wrote. Execution is a fixed server-side registry keyed by scenario id: no request field carries a command, script path or argv, and a run goes through the job queue so a slow scenario cannot hold the request. The demo's first path becomes browser-only, with the CLI kept as the documented fallback.

**Acceptance**

- [x] `GET /dashboard/demo` exists in `gateway/dashboard/routes.py`, requires `operator`/`admin` through `require_roles`, and renders one card per scenario with the control it exercises and the evidence it should produce
- [x] A scenario is started by a fixed registry (scenario id -> server-side callable); a run request with an unknown id is rejected with `404` or `422` and executes nothing, and no endpoint accepts a command string, a script path or argv
- [x] The egress canary block is reachable as a scenario, and `uv run pytest tests/test_dashboard_demo.py -q` proves the run reports `canary_leak` with empty delivered text
- [x] `readonly` and `analyst` sessions receive `403` on both the page and the run endpoint, and the four-eyes rule is unchanged for tickets created by a scenario
- [x] A tool-request scenario acts as the signed-in principal, never an `--actor-sub` supplied by the request, and approval still requires a second principal
- [x] The page lists at least `demo_classifier.py`, `demo_egress.py`, `demo_model_canary.py`, `demo_tool_request.py`, `demo_traffic.py` and `seed_demo_approval.py`, and each card states whether it needs the live model, GPU or a worker
- [x] `DEMO.md` Act 5 names the page as the first path, and `docs/adr/ADR-007.md` decision 2 lists the new route and the execution model

**Notes**

- Compound request, captured as one first step. The source ask had three strands; this item is the demo console. Left out and candidates for separate items: (a) dashboard improvements unrelated to demos, notably the `AUDIT_LOG_VIEW` record still deferred by ADR-007 decision 7; (b) scenarios with no existing script — a deterministic `429`/`Retry-After` demonstration for the ADR-013 limiter, approval expiry (DEMO.md §9 is manual), quarantine expiry; (c) a host-side `scripts/run_demo.py` if a browser console is judged too much surface for too little.
- Security note: exposing server-side entry points to a web session adds a dangerous primitive, so the item forbids request-supplied commands, paths and argv, reuses the existing RBAC dependency, and expects the execution model to be recorded in ADR-007 (or a new ADR) before implementation. The `demo_tool_request.py --actor-sub` flag must not become an impersonation path from the dashboard.
- Deduplication: IDEA-002 (WebSocket approvals) is dashboard transport, not a demo page; IDEA-006 (done) built the deterministic egress script itself and its acceptance names no UI; IDEA-011 (done) reconciled the rate-limit claim. No ADR in `docs/adr/` mentions a demo console or a scenario runner, and ADR-007 decision 2 enumerates the current three dashboard pages plus chat.
- Classification: `P2`/`v0.3` because ADR-008 decision 5 freezes new features inside a phase and no ADR-008 phase scope names a demo console; triage may downgrade to `P3` or pull it into v0.2 if the demo is treated as part of the current definition of done.
- Open questions for triage: whether runs execute in the gateway process, the ARQ worker or a dedicated compose service; and whether a run should write a new audit event type (an event-vocabulary change, like the one ADR-007 decision 7 defers for views) or structured logs only.

**Implementation notes (2026-11-11)**

- Started at explicit request while `inbox`/v0.3; the operator override is the same one used for IDEA-007. Triage questions were settled before coding: runs execute as an ARQ job with the result in Redis, runs write structured logs and a `demo.scenario` span only (no new audit event type), and the traffic scenario stays CLI-only.
- `GET /dashboard/demo` lives in `gateway/dashboard/routes.py` (read-only, `require_roles("operator", "admin")`); `POST /dashboard/demo/runs` and `GET /api/dashboard/demo/runs/{id}` live in `gateway/dashboard/demo.py`. The registry is `agent/demo/scenarios.py`: `SCENARIOS` maps a fixed id to a server-side handler, and the five cards with a handler show **Run scenario**.
- Security shape: the form carries `scenario_id` only; an unknown id is `404`, `demo_traffic` (no callable) is `422`, both before anything executes. The gateway captures `sub` and roles from the authenticated session and passes them to the job, so the request cannot supply an actor (the `--actor-sub` flag has no dashboard equivalent). Execution is asynchronous: the gateway writes `demo:run:<id>` in Redis and enqueues `run_demo_scenario_job`; the worker resolves the id, runs the scenario and updates the record; the page polls until terminal; results expire after an hour. Runs write only structured logs and a `demo.scenario` span — the canonical audit rows still come from the scenario's own effects.
- Runnable scenarios: `demo_classifier` (real classifier, rules fallback if models absent), `demo_egress` (real sanitizer/vault, deterministic), `demo_model_canary` (real model, raw completion never stored because it may carry the canary), `demo_tool_request` (signed-in principal, mutating tool so it suspends), `seed_demo_approval` (direct ticket seed for the queue). `demo_traffic` is listed but CLI-only: it drives `/v1/chat` for three principals and would need their tokens inside the gateway.
- Measured live against the rebuilt gateway and worker: `/dashboard/demo` returned 200 with all six scripts and five run buttons; a `demo_egress` run finished `succeeded` with `reason=canary_leak`, `delivered_chars=0`, `delivered_text=""`, `quarantined=yes`, `restored_tokens=1`; `demo_classifier` routed 3 of 4 samples local (ensemble, rules floor on); `demo_tool_request` produced ticket `f83c1fcb-…` with `initiator=56aded4e-…` (alice's `sub`); `seed_demo_approval` produced a second pending ticket. Alice's approval of her own ticket returned `403` ("four-eyes principle") and bob's returned `200`; `carol` got `403` on the page and the run endpoint; an unknown id got `404`; four `demo.scenario` spans are in the OpenLit trace store with `succeeded`.
- Tests: `tests/test_dashboard_demo.py` (9 tests) covers the six-script page, operator-only page/run/poll, unknown id executing nothing, CLI-only `422`, extra request fields not becoming command/actor, the real canary scenario's `canary_leak` + empty text, polling stopping at terminal, and the integration four-eyes path. `tests/test_dashboard.py` still passes. Full suite 630 passed / 2 `model_integration` skips; ruff check and format clean; mypy clean (70 files); pylint 10.00/10; `check_adrs.py`, `validate_tool_catalog.py --check`, `validate_rbac.py` and `recalculate_dread.py --check` all OK.
- Deferred as captured: the `AUDIT_LOG_VIEW` record, scenarios with no existing script (rate-limit `429`, approval expiry, quarantine expiry), and a host-side `scripts/run_demo.py`. The chat footer still points at `demo_egress.py`; Act 5 now points at the console first.
