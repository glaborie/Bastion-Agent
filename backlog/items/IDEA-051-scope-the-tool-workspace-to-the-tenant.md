### IDEA-051: Scope the tool workspace to the tenant

- status: inbox
- priority: P1
- phase: v0.3
- area: agent
- tags: tools, tenancy, filesystem
- depends-on: -
- spec: ADR-015
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`agent/tools/builtin.py:37-45` resolves a single `settings.tool_workspace_root` and
`read_file` (`:88-90`) drops `context` entirely. The catalog entry requires no role and no
approval (`docs/tools/v1.json:21-32`), so any authenticated principal reads the file another
tenant's approved write produced, and two tenants writing the same relative path overwrite each
other. Every other scope in the stack carries the tenant explicitly, which makes this the outlier.

No gateway route enqueues tool jobs today, so this is inherited by the first tool-calling path
rather than reachable now.

**Outcome**

Tool paths are namespaced per tenant and a read cannot cross a tenant boundary.

**Acceptance**

- [ ] A test shows tenant B cannot read a file tenant A wrote, and tenant A's content is unchanged
- [ ] The catalog entry and `docs/tools/v1.json` state the tenant scoping
- [ ] `uv run python scripts/validate_tool_catalog.py --check` passes
