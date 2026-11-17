### IDEA-067: Warm the DLP and classifier before the first chat turn

- status: inbox
- priority: P2
- phase: v0.4
- area: gateway
- tags: latency, startup, dlp, classifier
- depends-on: -
- spec: ADR-011
- created: 2026-11-17
- updated: 2026-11-17
- source: session report on 2026-11-17 ("the last call to /chat took a really long time in session 57d0d415…")

**Problem**

The first chat turn after a restart is several times slower than every later one,
because the guardrails are built lazily on first use. Measured on the running
stack, conversation `57d0d415954e451186e4c74111baf03c`:

| turn | total | breakdown |
|---|---|---|
| 1, 14:27:31.008 → 14:27:37.316 | **6.31 s** | 3.45 s before `DLP_REDACTION`, 43 ms classifier, 2.79 s OpenRouter, 10 ms egress |
| 2, 14:30:39.074 → 14:30:40.982 | 1.89 s | 1.80 s OpenRouter |

The 3.45 s is Presidio/spaCy construction: the gateway log shows
`Loaded recognizer: …` lines and `Presidio analyzer ready` at 14:27:34.4, i.e.
inside the first request, 3.4 s after it arrived. The gateway had been restarted
at 14:25 by a rebuild. Requests after that settle at 0.89-1.83 s against the same
provider.

`lifespan` in `gateway/main.py:59` configures logging, verifies the tool registry
and yields; it never touches `agent.dlp.presidio.get_analyzer` or the ONNX
ensemble, so the model files, the spaCy pipeline and the recognizer registry are
all paid for by whichever caller happens to arrive first. The same cold path
exists in the worker, and a container restart makes it happen on a schedule the
operator does not choose.

**Outcome**

The first user turn after `docker compose up -d gateway` costs what a steady-state
turn costs, and readiness reflects that honestly: the gateway does not report
healthy while the guards it will use are still cold, and a failure to load them
is a startup failure rather than a first-request 500. Decisions do not change —
warm-up builds the same analyzer and sessions, it does not alter thresholds,
detectors or routing. The change comes with a before/after measurement taken on
this stack, not a claim.

**Acceptance**

- [ ] `lifespan` (and the worker's startup) construct the Presidio analyzer and the ONNX ensemble before serving, through the same accessors the request path uses, so there is one instance and no duplicated initialisation
- [ ] A test pins it: with the constructors patched, starting the app calls both once, and a failure in either makes startup fail with a named error instead of surfacing on `POST /v1/chat`
- [ ] Measured on the stack: first-turn latency after `docker compose up -d gateway` is within the steady-state envelope, with the numbers and the method recorded in the item Notes (audit timestamps for `INPUT_RECEIVED` → `DLP_REDACTION` before and after)
- [ ] The health/readiness endpoint does not report ready before warm-up finishes, and `docker compose up -d` still converges (no deadlock with `models-init`, `db` or `redis` dependencies)
- [ ] `scripts/gate.sh` is green and `docs/TROUBLESHOOTING.md` documents the cold-start signature (`Presidio analyzer ready` inside the first request) if the chosen design leaves any lazy path behind

**Notes**

- Evidence is audit rows 766-770 and 771-775 plus `docker compose logs gateway` for 14:27-14:30; the classifier itself was warm (43 ms) because both graphs load in one session build — the delay here was Presidio, and the ONNX path deserves the same measurement in the acceptance run.
- The alternative worth considering is a documented warm-up request after `up` (`make warm`), which costs no startup semantics but leaves the trap for anyone who does not run it; preloading in `lifespan` is the option that makes the guarantee hold for every deployment.
- Out of scope: caching the classifier across restarts, making the model files smaller, and any change to thresholds or to the routing decision. This item only moves when the existing initialisation happens.
