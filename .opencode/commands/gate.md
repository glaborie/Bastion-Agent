---
description: Run the repository gate and report the verdict
agent: build
---

Run `scripts/gate.sh` in the current worktree and report what it says.

Argument, when present: `$ARGUMENTS`

- `docs` → `scripts/gate.sh --no-tests`
- `integration` → `scripts/gate.sh --integration` (needs `TEST_DATABASE_URL`)
- `evals` → `scripts/gate.sh --evals`
- empty → `scripts/gate.sh`

Then read `artifacts/gate/latest/summary.md` — the per-step logs are beside it if
a step needs more than its last 20 lines.

Report exactly three things:

1. the verdict line (`gate: N/M passed · wall … · failed: …`),
2. for each failed step, the cause in one sentence plus the file it points at,
3. the summary path.

Fix a failure only when it comes from the change in front of you. A failure
caused by something else — a stale worktree, another session's edit, a missing
service — is reported, not worked around.

Treat the gate list, thresholds, markers and assertions as fixed: the way to a
green run is a change to the code under test, never to the gate.

After one fix-and-rerun cycle, if it is still red, report and stop.
