### IDEA-061: Expose the tool catalog over stateless MCP with downstream upstreams behind the same gates

- status: inbox
- priority: P2
- phase: v0.6
- area: agent
- tags: mcp, tools, egress, rbac, audit
- depends-on: IDEA-059
- spec: ADR-009
- created: 2026-11-14
- updated: 2026-11-14
- source: session, design note on an MCP proxy against agent/tools/execution.py and docs/tools/v1.json, 2026-11-14

**Problem**

The four-gate tool governance of ADR-009 exists and is tested — catalog check with `-32003` (`agent/tools/errors.py:16`), role, schema, and the four-eyes fingerprint over `(tool_name, arguments)` (`db/tokens.py:24-26`) — but it is only reachable from the gateway and the ARQ worker. There is no `/mcp` route, no MCP client or dependency in the tree, and `docs/tools/v1.json` v1 keys three built-in tools by name alone, with no server, description hash or schema hash, so an external MCP client cannot call anything and an upstream MCP server cannot be admitted through the same gate. Graduate work in ADR-008 names "A2A (MCP)" in v0.6 but no ADR or item defines the surface. Admitting upstreams naively is the risk: their `tools/list` descriptions are attacker-controlled text that would become the model's view of the tool (tool poisoning), and the MCP revision in scope also defines server-initiated sampling, resources and prompts, which would let a server drive a model call outside the DLP, canary and ledger path.

**Outcome**

Northbound, Bastion is a stateless MCP resource server at `/mcp` authenticating agent tokens (IDEA-059): it validates the token's audience for the MCP surface, keeps no session, and never passes a caller token to an upstream. Southbound, Bastion is an MCP client to registered upstreams with its own credentials, an allowlisted base URL and an egress allowlist that refuses link-local and cloud-metadata addresses. Each `docs/tools/v1.json` entry gains `server`, `description_hash` and `input_schema_hash` (`read_only` and `required_role` already exist), and `tools/list` serves the catalog text — never the upstream's live description — so a description or schema drift disables the tool and writes a `SECURITY_INCIDENT`, the same way an approved ticket whose tool left the catalog is refused at execution (`agent/tools/execution.py:239-245`). `tools/call` runs the existing gates in order — catalog (`-32003`), role and agent allowlist, pinned schema validation, then four-eyes for anything not proven read-only — with the ticket fingerprint binding `(server, tool, arguments)`, and `read_only` defaults to false because upstream hints are advisory. Results are treated as untrusted: fenced, size-capped and DLP-scanned, and a result carrying PII keeps the next turn on the local route exactly as a PII prompt does. `validate_tool_catalog.py --discover` diffs an upstream's `tools/list` against the catalog for review, `traceparent` is forwarded so tool spans join the chat trace, and sampling, resources and prompts are refused by default.

**Acceptance**

- [ ] Spike result recorded before any code: either the Python MCP SDK supports the 2026-07-28 revision, or the thin stateless layer built in-tree is chosen, with the pinned revision and the reason named in the ADR (phase 0)
- [ ] A stateless `POST /mcp` serves `tools/list` and `tools/call` with no `Mcp-Session-Id` and no `initialize` handshake, and a request whose `Mcp-Method` or `Mcp-Name` header disagrees with its body is rejected before dispatch (phase 1)
- [ ] `tools/list` returns the catalog's descriptions and hashes for the built-in tools, a tool registered in code but absent from `docs/tools/v1.json` never appears, and a name the catalog does not hold returns `-32003` with no tool execution (phase 1)
- [ ] A mutating built-in tool suspends for four-eyes and runs only on approval, role and schema refusals write the same ledger rows as the native path, and the ticket fingerprint includes the server identifier (phase 1)
- [ ] A token minted for `bastion-gateway` (`settings.py:88`) is refused at `/mcp` with 401, and `/mcp` accepts only the MCP audience issued to the agent client, both asserted without a model or tool call (phase 1)
- [ ] An upstream that changes a tool description or input schema has that tool disabled on the next discovery, with a `SECURITY_INCIDENT` naming the server and tool and no upstream-issued text ever reached through `tools/list` (phase 2)
- [ ] The upstream allowlist refuses a link-local or metadata address and a redirect to one, the upstream sees Bastion's own credential rather than the caller's token, and `traceparent` from the caller is forwarded (phase 2)
- [ ] `uv run python scripts/validate_tool_catalog.py --discover <server>` lists added, removed and changed upstream tools and exits non-zero on drift (phase 3)
- [ ] Server-initiated sampling, resources and prompts are refused by default, and the refusal is asserted in a test rather than left to the SDK (phase 4)
- [ ] `tests/data/goldens.jsonl` gains the MCP gate cases (`-32003` before upstream contact, description drift incident, wrong audience, sampling refused) and `uv run python scripts/run_evals.py` gates them at `1.000` (phase 3-4)
- [ ] An ADR records the MCP surface, the DCR-to-Client-ID-Metadata-Document stance, the Enterprise-Managed Authorization extension decision and the per-surface audience; `THREAT_MODEL.md` gains the MCP egress and tool-poisoning rows; `docs/tools/v1.json` and `validate_tool_catalog.py --check` agree; `scripts/gate.sh` passes

**Notes**

- Deduplication: no item or ADR defines an MCP surface; ADR-008 v0.6 names "A2A (MCP)" as a phase item, ADR-009 governs the gate this reuses, and IDEA-059 is the agent-token item the northbound side depends on. IDEA-060 is an OpenAI-compatible HTTP facade, a different protocol with a different client contract, so it is not the same problem. IDEA-052 covers four-eyes fields in the ledger hash and is unchanged here.
- Classification: `P2`/`v0.6`/`agent`. New capability, no invariant broken today, and ADR-008 freezes features inside a phase; v0.6 is the only phase that names MCP. `area: agent` because the gate, the catalog and the upstream client live in `agent/tools`; `gateway` is the fair alternative for the northbound route, and `security` for the egress and poisoning invariants.
- Phasing inside the item, mirroring IDEA-023: phase 1 is the built-in tools over stateless MCP with no upstream and is the first acceptance target; phase 2 adds one pinned read-only upstream; phase 3 is the `--discover` tooling; phase 4 is the decisions on sampling, resources and per-user delegation. The acceptance box names its phase so a builder can stop after phase 1 without the rest being silently dropped.
- Open questions for triage, deliberately not decided: whether `server` is a field on an existing catalog entry or a second catalog file per server (the current schema is strict and rejects unknown fields, so either choice changes `agent/tools/catalog.py` and `docs/tools/v1.json` together); how descriptions and schemas are canonicalised before hashing (the same problem `db/hashing.py` already solves for payloads); and whether dynamic client registration is refused outright in favour of Client ID Metadata Documents, which the revision prefers.
- Two consequences to plan for, not discover: `fingerprint_request` (`db/tokens.py:24`) gains the server, so pending tickets created before the change recompute to a different fingerprint — either they fail closed with a documented reason or the verifier accepts both forms; and a per-surface audience means the Keycloak client needs an audience mapper for the MCP resource, since today one `keycloak_audience` covers the whole gateway.
- The 2026-07-28 revision facts in the design note — no `Mcp-Session-Id`, version in `_meta`, `Mcp-Method`/`Mcp-Name`, W3C trace context, DCR deprecation, Enterprise-Managed Authorization as an extension — are the spike's input, not established here; the ADR must cite the revision text it verified.
