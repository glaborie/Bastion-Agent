### IDEA-109: Rate-limit the /mcp surface per principal

- status: ready
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

- [ ] A request over the MCP budget answers `429` with `RateLimit-Limit`, `RateLimit-Remaining` and
      `Retry-After`, and no tool executes and no ticket is created
- [ ] An unavailable limiter answers `503` (fail closed), not an unmetered request
- [ ] Agents charge their `budget_key` and two agents of one owner do not share a bucket, asserted with
      a recording limiter
- [ ] `rate_limit_enabled: false` makes the surface unmetered again, matching the other scopes
- [ ] `uv run pytest tests/test_mcp.py -q` and `scripts/gate.sh` pass

**Notes**

- Reuses `RateLimiter.consume` and the `mcp` scope, so the bucket script, headers and refusal shape are
  the ones already tested for `dashboard` and `chat`; nothing new is invented for this surface.
- The charge is per HTTP request (list and call both), which is the unit the other scopes meter. Pricing
  a tool call by arguments or output size is a separate decision and is not taken here.
- Ordering matters: the registry refusal (`403`) runs before the bucket is charged, so a suspended agent
  cannot drain its budget while being refused, and the body is read only after the charge, so a
  refused caller cannot make the gateway buffer anything.
