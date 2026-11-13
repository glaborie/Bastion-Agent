### IDEA-027: Cache semantically equivalent completions to avoid repeated model calls

- status: inbox
- priority: P2
- phase: v0.5
- area: agent
- tags: semantic, cache, redis, latency
- depends-on: -
- spec: -
- created: 2026-11-12
- updated: 2026-11-12
- source: session request on 2026-11-12 ("add a semantic cache component to avoid unnecessary LLM calls for similar queries")

**Problem**

Every chat turn ends in a model call that nothing can short-circuit:
`gateway/routers/chat.py` reaches `model_router.complete(...)` at line 446
unconditionally after DLP, classification and routing, and
`agent/routing/client.py::ModelRouter.complete` (line 261) always posts the
messages to OmniRoute. A search for an answer cache finds none — `agent/`,
`gateway/` and `settings.py` hold only `functools.lru_cache` singletons (the
Presidio analyzer, the tool catalog, the model router, the JWKS client, the
settings object) and `gateway/evals.py`'s mtime-keyed report cache, while Redis
carries vault, canary, quarantine, approval and rate-limit keys with no
completion namespace. The same question asked twice in one session, or the same
question paraphrased, therefore pays full inference twice; on this host that
duplicates queue behind the single RTX 3060 Ti that ADR-004 records, and every
`PUBLIC` duplicate is a billed cloud completion. The opposite gap matters too:
`gateway/routers/audit.py` states that PII payload responses are never cached,
so any completion cache has to be argued against an existing no-cache posture
rather than added casually.

**Outcome**

A cache in front of the completion call answers a repeated or semantically
equivalent question without a model request, and the saving is measurable in hit
rate and latency; a near-duplicate whose answer would differ misses and calls
the model. Lookup happens after DLP and classification, and the entry is keyed
by tenant, model alias and classification label, so a turn can never receive
another tenant's answer or a `cloud-primary` answer for a `CONFIDENTIAL` prompt.
Entity markers stay session-scoped: egress restores them for the requesting
session, and a hit never delivers an unresolved `{{ENTITY:...}}` token. The
similarity backend is injectable, the threshold and TTL are settings keys, and
the feature ships off by default until an ADR records the key, the scope, the
eviction and the audit shape.

**Acceptance**

- [ ] `uv run pytest tests/test_semantic_cache.py -q` proves that two identical turns in one session produce one model call (a recording router counts them) and deliver the same answer text, with the second turn served from the cache
- [ ] A paraphrase above `SEMANTIC_CACHE_SIMILARITY_THRESHOLD` hits and a near-miss below it misses and calls the model; both are pinned with an injectable fake similarity backend, so the suite needs no network call and no model download
- [ ] The same text routed two ways never shares an entry: a `pii_detected` turn on `local-llama` does not read a `cloud-primary` entry, and a tenant B turn does not read a tenant A entry, both asserted with identical prompt text
- [ ] A hit cannot deliver another session's marker: a test replays a cached answer whose markers were minted in a different session and asserts the caller gets either a fully restored answer or a miss, never a `{{ENTITY:...}}` token
- [ ] The turn is still audited: a cache hit is visible on the ledger (the existing rows' metadata, or the event shape the ADR decides) and the hit still writes the DLP and egress rows for that turn, asserted by comparing the hit and miss paths in `tests/test_semantic_cache.py`
- [ ] `SEMANTIC_CACHE_ENABLED=false`, `SEMANTIC_CACHE_SIMILARITY_THRESHOLD` and `SEMANTIC_CACHE_TTL_SECONDS` are settings keys documented in `.env.example`; with the flag off `uv run pytest -q` passes and the recording router observes exactly the pre-change model-call count
- [ ] `uv run python scripts/benchmark_semantic_cache.py` reports hit rate, model calls avoided and p95 latency with the cache on and off over a repeated prompt corpus, and those numbers are recorded in the item and the ADR
- [ ] The ADR (a new one, or an amendment to ADR-004) records what the cache is not — not a confidentiality decision, not a substitute for DLP, canary or egress, and not a PII store — and `uv run python scripts/check_adrs.py` passes

**Notes**

- Deduplication: grepped `BACKLOG.md`, `docs/adr/` and `HANDOVER_SPEC.md` for `semantic`, `cache`, `embedding`, `dedup`, `vector`, `similar` and `cost`. The hits are IDEA-015 (semantic disclosure at egress), the `semantic` tag on IDEA-015/IDEA-018, IDEA-003/IDEA-007's classifier latency and calibration budgets, and `lru_cache` in code; no backlog item and no Accepted ADR covers a response or completion cache, so there is nothing to merge.
- `spec: -` is deliberate: no decision governs caching. ADR-004 owns which alias a prompt takes, not whether a model is called at all, and ADR-012 owns the egress contract a hit must still satisfy; this item's first deliverable is the ADR that decides the key, the scope and the audit shape, so there is nothing to cite yet.
- Classification: `P2`/`v0.5`/`agent`. New capability with no stated invariant broken, so not `P0`/`P1`; ADR-008 decision 5 freezes features inside a phase, the current phase is `v0.3`, and no phase line names caching. `v0.5` is the nearest home because its scope ends with "Token and cost budgets remain open", which is the concern this serves; `v0.6` (multi-provider OmniRoute, local model hot-swap) is the fair alternative, and triage may move it there or reject it as premature while the stack is a single-host demo. `area: agent` because the stage sits beside `agent/dlp`, `agent/routing` and `agent/egress` in the turn pipeline; `db` fits only the Redis keys and `gateway` only the `chat()` call site.
- Open questions for triage, deliberately not decided: **where the embedding runs** — a cloud embedding API would send prompt text off-host, which contradicts ADR-002/ADR-004 for `CONFIDENTIAL` prompts, so an on-box embedder or an exact-hash first slice is the conservative default; **where the vectors live** — Postgres with pgvector, a Redis vector index, or an in-process dict with no persistence; **whether a hit may be served while the routed backend is down**, since ADR-004 decision 4 fails closed on `local-llama` and a cached answer must not look like a live confidential completion; and **whether entries may be shared across principals inside one tenant**, which is where most of the saving is and the largest leak surface.
- Honest limits to record in the ADR rather than paper over: a similarity threshold is a false-positive budget — a hit on a question that only looks the same serves a wrong answer with no way for the caller to tell, so its measured near-miss behaviour matters more than its hit rate; the cache is a PII-adjacent store, so its TTL should be short and its contents should be markers or post-redaction text rather than raw prompts; and the embedding cost is paid per turn whether or not the lookup hits, so the component can make the median turn slower while it removes duplicate model calls.
- Scope: one cache stage plus the ADR. Out of scope: a separate exact-match cache item, prefix or KV caching inside `llama.cpp`, OmniRoute provider-side caching, and any change to `/v1/chat`'s request schema. Intake only — no implementation, dependency, settings, test, compose or ADR edit is part of this capture.
