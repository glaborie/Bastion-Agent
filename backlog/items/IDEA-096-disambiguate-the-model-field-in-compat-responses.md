### IDEA-096: Disambiguate the model field in compat responses

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, client-compat, model
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-20
- source: six-finding OpenAPI review of the compat surface, 2026-11-20

**Problem**

In the compat surface `model` carries three different meanings depending on the request and the verdict:

- on the request, `bastion-auto` / `bastion-local` are routing hints, not model ids
  (`gateway/routers/openai_compat.py:188-196`);
- on an allowed completion, the response echoes the provider's model id (`model=completion.model`,
  `gateway/routers/chat.py:847`), e.g. `openai/gpt-4o-mini`;
- on a blocked turn, the response says `"gateway"` (`:576`), a sentinel declared in `ChatResponse`'s
  docstring ("`model` is `gateway`, not a provider").

A client that keys logging, cost attribution or UI text off `model` therefore sees an alias, a provider id
and a service name in the same field of the same response shape. `bastion-auto` and `"gateway"` are not
model ids, and nothing in the document says so.

**Outcome**

One documented rule, recorded in ADR-026 decision 4 and visible in the document: `model` identifies what
actually served the turn, always in the same namespace, and a turn with no provider is identified by a
declared marker that cannot be mistaken for a model id — either a stable reserved value the document names,
or a separate `bastion.blocked`-derived signal with `model` set to the requested alias. The three cases
become distinguishable without a fourth meaning, the blocked-turn signal stays `bastion.blocked: true`, and
`/v1/models` remains the list of what may be asked for. Native `/v1/chat` keeps its current shape unless the
amendment deliberately aligns it.

**Acceptance**

- [ ] Three contract tests — a normal turn, a `bastion-local` turn and a blocked turn — assert the documented rule for `model` and that the three are distinguishable by a client that only reads `model` plus `bastion.blocked`
- [ ] ADR-026 decision 4 states the rule, the reserved value if one is chosen, and why the blocked case is not a provider id; `README.md` says what a compat client should key on
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_chat.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `model field`, `bastion-auto`, `gateway`
  sentinel. IDEA-090 (dropped) touched the blocked-turn payload but only its `content`; IDEA-060 built the
  surface and ADR-026 decision 4 records `model: gateway` deliberately, so this is an amendment, not a bug
  report. No item was merged.
- Open question for triage, which decides the shape: echoing the requested alias would make `model` a
  client-owned value but hide what served the turn, and any client comparing `model` to its request would
  then always match. Adding a `served_model` field is cleaner but is a compat-surface addition that needs
  ADR-026 to say so.
