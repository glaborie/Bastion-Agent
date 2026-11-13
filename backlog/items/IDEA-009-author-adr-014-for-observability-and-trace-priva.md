### IDEA-009: Author ADR-014 for observability and trace privacy

- status: done
- priority: P2
- phase: v0.2
- area: security
- tags: tracing, privacy, opentelemetry, config
- depends-on: -
- spec: -
- created: 2026-11-10
- updated: 2026-11-11
- source: audit of docs/adr/ coverage against README.md section Telemetry, 2026-11-10

**Problem**

The trace pipeline exists in code but no Accepted ADR governs it: `telemetry.py`
holds the span attributes, the GenAI conventions, the httpx instrumentation,
`DEFAULT_EXCLUDED_URLS` and `OTEL_TRACES_SAMPLER_RATIO`; `config/otel/` holds
four collector files whose second `--config` overlay is chosen by
`OTEL_REMOTE_EXPORT_CONFIG`; and the rule that prompt/completion text, tool
arguments and per-user identity are never exported lives only in README
section Telemetry and in `annotate_span`'s docstring. ADR-011 mentions telemetry
once, in passing, and is not a decision about traces. A reviewer therefore cannot
tell which parts are deliberate policy and which are incidental, and a future
edit can delete the exclusion list or add a payload attribute without contradicting
any recorded decision.

**Outcome**

`docs/adr/ADR-013.md` (title "Observability & Trace Privacy", Status Accepted)
records the trace architecture as decisions: the gateway/worker to OTLP collector
topology and the overlay-plus-recreate procedure; the attribute allow-list and the
fields that are never exported; the exclusion and sampling policy that keeps
dashboard polling and the two worker cron sweeps untraced; and backend neutrality
— OpenLit, Langfuse and Arize are interchangeable through a collector overlay, so
switching backend is a config change, not a code change. The ADR is indexed in
`docs/adr/ADR-Index.md` and no behaviour changes.

**Acceptance**

- [x] `docs/adr/ADR-013.md` exists with `# ADR-013: ...`, the Status/Date/Last modified block, a two-paragraph `## Context`, a numbered `## Decision` and `## Consequences` with Pros and Cons
- [x] `uv run python scripts/check_adrs.py` passes with the new file and its `ADR-Index.md` row
- [x] The Decision section names `config/otel/otel-collector-config.yaml`, the overlay selected by `OTEL_REMOTE_EXPORT_CONFIG`, and the `docker compose up -d --force-recreate otel-collector` procedure
- [x] The Decision section states the never-exported fields (prompt and completion text, tool arguments, per-user identity) and the exclusions in `DEFAULT_EXCLUDED_URLS` plus the untraced cron sweeps
- [x] The Decision section states that OpenLit, Langfuse and Arize are selected by overlay only, and that the overlay in force is runtime configuration rather than architecture

**Notes**

- `spec: -` is deliberate: the gap is that no ADR governs the trace pipeline yet, so there is nothing to cite as the governing decision. ADR-011 mentions telemetry only in a Pros bullet; that is not a decision about tracing.
- Classified `security` rather than `infra` because the load-bearing content is the trace-privacy invariant (what may never leave the host); the collector topology rides along with it.
- Scope is documentation only. No code, config or compose change is part of this item; the live backend choice (self-hosted OpenLit while the Langfuse quota cools down) belongs in `.env`, which is gitignored, and must not be recorded as architecture.
- Open question for triage: whether ADR-013 should also absorb the collector `filter/noise` drop rules for ASGI send/receive spans and 404s, or leave them as an infra detail owned by `config/otel/`.
- 2026-11-10 numbering note: ADR-013 was taken by the per-principal rate-limiting decision (`docs/adr/ADR-013.md`, shipped in v0.2). When this item is worked, author **ADR-014** for observability instead; read every `ADR-013` in the Outcome and Acceptance above as `ADR-014`. The index row and `check_adrs.py` expectations are otherwise unchanged.

**Implementation notes (2026-11-11)**

- Numbering resolved per the item's own 2026-11-10 note: `ADR-013` is the per-principal rate-limiting decision, so the observability record is `docs/adr/ADR-014.md` and every `ADR-013` in the Outcome and Acceptance was read as `ADR-014`. The index row is `| 014 | Observability & Trace Privacy | Accepted |`; `check_adrs.py` reports `OK: 14 ADRs, index consistent`.
- Every decision was written from the code, not from the README: `telemetry.py` (provider, `BatchSpanProcessor` 2048/2 s/10 s, `DEFAULT_EXCLUDED_URLS`, `ParentBased(TraceIdRatioBased)`, `annotate_span`, the scoped `instrument_http_client`), `gateway/main.py` and `agent/runtime.py` (both call `configure_tracing`), `agent/runtime.py` (only jobs are traced; the two 30 s cron sweeps create no span), `config/otel/` (base owns receivers/processors/exporters, each overlay owns only `service.pipelines.traces.exporters`), and `docker-compose.yml` (second `--config` mounted from `OTEL_REMOTE_EXPORT_CONFIG`, loopback-only ports, `host.docker.internal:host-gateway` for OpenLit).
- The item's open question about the collector `filter/noise` rules is resolved by recording them in decision 4 as collector-owned volume control: ASGI send/receive and 404 spans are dropped before the exporters, so `debug` and every remote backend see the same set, and the rule sits in the same pipeline as the exclusions rather than being an undocumented infra detail.
- Trace-privacy allow-list is stated positively (the attributes actually emitted by `gateway/routers/chat.py`, `agent/runtime.py` and `agent/routing/client.py`) and negatively (prompt text, completion text, tool arguments, tool output, vault markers and plaintext, subject/username/email/actor id). Verified by grep that no actor or subject attribute is set on any span.
- Docs-only, as scoped: no code, config, compose or test change. `scripts/gate.sh` → 10/10 (pytest 583 passed, 33 skipped, 43 deselected, pylint 10.00/10, mypy clean, all five policy scripts OK).
- Observed while verifying, deliberately not changed (outside this item): `README.md` still lists "Better Stack" as a backend although no exporter exists for it, and `DEFAULT_EXCLUDED_URLS` names `/metrics` although the gateway serves no such route — both harmless, both better handled by a docs/telemetry cleanup item than by a drive-by edit here.
