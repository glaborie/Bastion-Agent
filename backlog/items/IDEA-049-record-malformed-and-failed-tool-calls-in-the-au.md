### IDEA-049: Record malformed and failed tool calls in the audit ledger

- status: ready
- priority: P1
- phase: v0.3
- area: agent
- tags: audit, tools, ledger
- depends-on: -
- spec: ADR-010
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`definition.validate_arguments(arguments)` raises before `_record_accepted`
(`agent/tools/execution.py:161`). `_execute_now` writes a `TOOL_EXECUTED/failed` row and then
re-raises (`:498-511`) inside `session_scope`, which rolls back. The worker's `except
ToolArgumentError` (`agent/runtime.py:294`) and `except ToolError` (`:316`) return without
calling `_persist_refusal`, which exists for exactly this case.

So a denied call is recorded and a malformed or failed one is invisible, contradicting "every
transition appends a hash-chained audit record in the same transaction as the state change".
Because `read_file` error strings distinguish missing file, traversal refusal and non-regular
file (`agent/tools/builtin.py:127-138`), this is an unlogged workspace-enumeration oracle.

**Outcome**

Every tool request that reaches the guard leaves exactly one terminal ledger row, including
invalid arguments and handler failures, and never two.

**Acceptance**

- [ ] A malformed `execute_file_write` leaves one audit row for the actor
- [ ] A failing `read_file` leaves one audit row for the actor
- [ ] A test asserts the ledger holds one row, not two, after a refusal
