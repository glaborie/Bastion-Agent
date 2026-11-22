### IDEA-109: Rate-limit the /mcp surface per principal

- status: done
- priority: P2
- phase: v0.5
- area: gateway
- tags: mcp, rate-limiting, abuse
- depends-on: IDEA-107
- spec: ADR-028
- created: 2026-11-22
- updated: 2026-11-22
- source: owner review of the merged /mcp surface, 2026-11-22

**Problem**

`/mcp` is raw ASGI, so it is outside the FastAPI dependency graph where every other surface takes
`rate_limit(...)`. A valid MCP token can issue `tools/list` and `tools/call` without bound: the only
limit that applies today is the 4 MiB body ceiling and `tool_max_argument_bytes`, both of which bound
one request, not the request rate. An agent that loops can keep the gateway, Redis and the ledger busy
indefinitely, and the per-agent budget ADR-027 introduced (`agent:<id>`, exhausted on the chat route)
does not cover this entry point.

Strix ruled this out on the grounds that the reachable agent already had an unbounded chat path, but
the chat path is priced in tokens by ADR-020 and MCP is not priced at all.

**Outcome**

Every MCP request is charged to the caller's existing bucket, using the same Redis token bucket the
dashboard and chat scopes use: agents charge `agent:<id>` (their registry `budget_key`) and humans
charge their subject, so one principal's MCP traffic cannot consume another's budget. A refusal is an
HTTP `429` with the same `RateLimit-*` and `Retry-After` headers as the other scopes, and an
unavailable limiter is a `503` rather than an unmetered pass. The budget is a setting
(`rate_limit_mcp_per_window`, same window as the other scopes) so it is tunable without a code change.

**Acceptance**

- [x] A request over the MCP budget answers `429` with `RateLimit-Limit`, `RateLimit-Remaining` and
      `Retry-After`, and no tool executes and no ticket is created
- [x] An unavailable limiter answers `503` (fail closed), not an unmetered request
- [x] Agents charge their `budget_key` and two agents of one owner do not share a bucket, asserted with
      a recording limiter
- [x] `rate_limit_enabled: false` makes the surface unmetered again, matching the other scopes
- [x] `uv run pytest tests/test_mcp.py -q` and `scripts/gate.sh` pass

**Notes**

- Reuses `RateLimiter.consume` and the `mcp` scope, so the bucket script, headers and refusal shape are
  the ones already tested for `dashboard` and `chat`; nothing new is invented for this surface.
- The charge is per HTTP request (list and call both), which is the unit the other scopes meter. Pricing
  a tool call by arguments or output size is a separate decision and is not taken here.
- Ordering matters: the registry refusal (`403`) runs before the bucket is charged, so a suspended agent
  cannot drain its budget while being refused, and the body is read only after the charge, so a
  refused caller cannot make the gateway buffer anything.

**Implementation**

- `mcp` joined `RateLimitScope` and `_SCOPES`, with `_limit_for` reading the new
  `rate_limit_mcp_per_window` (default 120, same window as the other scopes), so the bucket script,
  headers and refusal shape are the ones already tested for `dashboard` and `chat`.
- `McpCaller` carries `rate_limit_subject`: the registry `budget_key` for an agent (so two agents of one
  owner do not share), the subject for a human. `_charge` runs after the registry check and before the
  body is read, so a suspended caller drains no budget and a refused one makes the gateway buffer
  nothing; `429` carries `RateLimit-*` and `Retry-After`, an unavailable limiter is `503`.
- `rate_limit_enabled: false` short-circuits the charge, matching the other scopes.
- Verified: `pytest tests/test_mcp.py -q` is 20 passed (charge identity and limit, 429 headers with no
  ticket, 503, agent budget key, disabled short-circuit); `scripts/gate.sh --integration` is 14/14.
- This branch also carries the Strix fix from #166 (`ddb3c60`): PR #166 was merged before that commit was
  pushed, so the body/argument ceilings never reached master. It is re-applied here rather than left
  behind.
