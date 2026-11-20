### IDEA-101: Give the read-only list routes a response schema

- status: inbox
- priority: P3
- phase: v0.5
- area: gateway
- tags: openapi, rbac, client-compat, tooling
- depends-on: -
- spec: -
- created: 2026-11-20
- updated: 2026-11-20
- source: OpenAPI review of the read surface, 2026-11-20 ("responses discoverable only by calling them")

**Problem**

Three list endpoints declare a `200` with no body shape, so the document describes nothing a
client generator can use:

- `GET /v1/models` (`gateway/routers/openai_compat.py:326-345`) returns
  `dict[str, Any]`; the document says `{"type": "object", "additionalProperties": true}`.
- `GET /api/audit` (`gateway/routers/audit.py:79-112`) returns
  `{"records": [...], "next_before_id": ..., "has_more": ...}`, but the document's 200 schema is
  title-only — no `type`, no properties.
- `GET /api/approvals` (`gateway/routers/approvals.py:112-125`) returns
  `{"approvals": [...], "count": ...}`, same title-only schema.

Both audit and approvals serve a different representation when the request carries the htmx
header (`is_htmx(request)`), an HTML partial that the document does not mention either. So the JSON
shape, the HTML branch and the conditional behaviour are all discoverable only by calling the
routes and reading their code.

**Outcome**

Each of the three routes declares its `200` body: `ModelList`/`Model` for `/v1/models` in the
OpenAI list shape, an audit page schema over the existing `AuditRecordOut`, and an approvals page
schema over the existing `ApprovalOut`. The dual-answer routes say in their description that an
htmx request receives the polling partial and the plain request the JSON page, so a reader can tell
which representation the schema describes. Nothing about the responses, the RBAC roles or the
pagination changes.

**Acceptance**

- [ ] A test reads `app.openapi()` and asserts each of the three `200` schemas names its properties (`/v1/models` → `object`/`data`; `/api/audit` → `records`/`next_before_id`/`has_more`; `/api/approvals` → `approvals`/`count`) instead of an empty or title-only schema
- [ ] The audit and approvals operation descriptions state the htmx partial branch, so a generated client is not told the HTML branch is the JSON one
- [ ] The declared schemas reuse the models the handlers already build (`AuditRecordOut`, `ApprovalOut`) rather than a second copy, so a field added to a row appears in the document
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_dashboard.py tests/test_dashboard_roles.py tests/test_approvals.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `openapi`, `response_model`,
  `additionalProperties`, `/api/audit`, `/api/approvals`, `htmx`. IDEA-092/097/100 document the
  compat chat route and its errors; IDEA-099 questions `/v1/models`' role gate, not its schema;
  IDEA-101 is the read surface those leave untouched. No item was merged.
- `spec: -`: no ADR fixes the shape of these payloads — ADR-015 owns the ledger's hash chain, ADR-007
  the role matrix — so this records a contract the code already has rather than amending a decision.
- `P3`: nothing is wrong at runtime; the cost is a generator that produces untyped lists and a
  reader who has to call the endpoint. The same gap is general across the app, so triage may prefer
  to widen it into one document-completeness item (see IDEA-093's note about a committed snapshot) —
  these three are the ones a client actually reads.
- Open question for triage: whether the htmx branch deserves a `text/html` entry in the document or
  only a sentence, since htmx is an internal consumer and no external client sets the header.
