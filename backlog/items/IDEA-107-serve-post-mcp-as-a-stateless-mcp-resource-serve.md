### IDEA-107: Serve POST /mcp as a stateless MCP resource server over the guarded catalog

- status: active
- priority: P2
- phase: v0.5
- area: gateway
- tags: mcp, tools, rbac, audit, openapi
- depends-on: -
- spec: ADR-028
- created: 2026-11-22
- updated: 2026-11-22
- source: split out of IDEA-061 phase 1 at the owner's direction, 2026-11-22

**Problem**

There is no `/mcp` route: the ADR-009 gates and the versioned catalog are reachable only from the
gateway routes and the ARQ worker, so an external agent tool client has nothing to speak to. IDEA-061
carried the northbound route as its phase 1, but phases 2-4 (upstream MCP client, discovery tooling,
sampling/resource stance) are a different kind of work on a different surface, and the route is what
the rest depends on. Split out so the route can land and be reviewed on its own.

ADR-028's spike settled the transport decision (use the official SDK, stateless wire, ours auth), but
its wording predates the installed API: `mcp==2.3.0` is the v2 line, where the low-level `Server`
takes `on_list_tools`/`on_call_tool` as constructor keyword arguments instead of decorators, and
`streamable_http_app(stateless_http=True)` exists on `MCPServer`, not on the low-level `Server`
(which is served through `StreamableHTTPSessionManager`). ADR-028 is amended to record the version and
that API shape; this item records the concrete wiring it picks.

**Outcome**

`POST /mcp` is a stateless MCP resource server over the approved catalog: no `Mcp-Session-Id`, no
`initialize`, an exact path that answers without a 307, and a Bearer wall that validates the MCP
audience (never the gateway audience) before the MCP app sees the request. `tools/list` serves the
catalog's pinned description and input-schema digests — never the live registry text — and a tool that
is registered in code but absent from `docs/tools/v1.json` never appears. `tools/call` runs the
existing gates in order (catalog `-32003`, role, agent allowlist, pinned schema, then four-eyes for
anything not proven read-only) through `request_tool_execution`, with the ticket fingerprint binding
the server identifier as well as the tool and arguments. A request whose `Mcp-Method`/`Mcp-Name`
header disagrees with its body is refused before dispatch, and the legacy leg (no `params._meta`) is
refused so that check cannot be bypassed. Server-initiated sampling, resources and prompts stay
unavailable by construction.

**Acceptance**

- [ ] A stateless `POST /mcp` serves `tools/list` and `tools/call` with no `Mcp-Session-Id` and no `initialize` handshake, answers the exact path without a redirect, and a request whose `Mcp-Method` or `Mcp-Name` header disagrees with its body is rejected before dispatch
- [ ] A request without the modern `params._meta` envelope is refused, so the legacy leg cannot skip the header check
- [ ] `tools/list` returns the catalog's descriptions and `description_hash`/`input_schema_hash` for the built-in tools, a tool registered in code but absent from `docs/tools/v1.json` never appears, and a name the catalog does not hold returns `-32003` with no tool execution
- [ ] A mutating built-in tool suspends for four-eyes and runs only on approval, role and schema refusals write the same ledger rows as the native path, and the ticket fingerprint includes the server identifier
- [ ] A token minted for `bastion-gateway` (`settings.py:92`) is refused at `/mcp` with `401`, and `/mcp` accepts only the MCP audience issued to the agent client, both asserted without a model or tool call
- [ ] `uv run pytest tests/test_mcp.py -q` and `scripts/gate.sh` pass, and ADR-028 names the wiring this item chose

**Notes**

- Split, not duplication: these are IDEA-061's phase-1 acceptance boxes, moved here verbatim in
  substance. IDEA-061 keeps phases 2-4 (upstream client, `--discover` tooling, sampling/resources
  stance, goldens, threat-model rows) and now declares `depends-on: IDEA-107`, because there is no
  northbound surface for an upstream to hang off until this lands.
- The catalog prerequisite (`server`, `description_hash`, `input_schema_hash` on every entry plus the
  parser and drift checks) was drafted on the `idea-061` branch and is preserved in closed PR #165.
  It belongs with this item, since `tools/list` is what serves those digests; re-apply it here rather
  than re-inventing a second hashing rule.
- Fingerprint consequence: `fingerprint_request` (`db/tokens.py:24`) gains the server, so pending
  tickets created before the change recompute to a different fingerprint. Choose and document one of
  the two IDEA-061 names: fail closed with a stated reason, or accept both forms in the verifier.
- Per-surface audience: today one `keycloak_audience` (`settings.py:92`, `bastion-gateway`) covers the
  whole gateway, and each client carries one `bastion-gateway-audience` mapper. The MCP surface needs
  its own audience and a mapper for the agent client in `config/keycloak/realm-export.json`;
  `validate_rbac.py --strict` is the check that keeps the agent clients consistent.
- Dependency direction is deliberate: IDEA-107 is standalone and buildable today; IDEA-061 is not.
- Open question for triage: whether `/mcp` is mounted in the existing gateway process (one image, one
  lifespan, one DLP path) or served as its own service. Mounting is assumed above because the gates
  and the ledger already live there, and it keeps the audit trail in one transaction.

**Verification route**

`pytest tests/test_mcp.py` plus the SDK-level assertions from ADR-028's spike (no handshake, no session
header, `-32020` before dispatch, `-32601` for resources); then `scripts/gate.sh`.
