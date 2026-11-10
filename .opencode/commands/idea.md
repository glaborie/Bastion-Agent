---
description: Capture an idea in BACKLOG.md without implementing it
agent: backlog
subagent: true
---

Capture this idea in `BACKLOG.md` following the `backlog-intake` skill:

$ARGUMENTS

Load the `backlog-intake` skill first. Deduplicate before writing, append exactly
one item with the next free IDEA-NNN id, classify it, then run
`uv run python scripts/check_backlog.py --write` and report the id,
classification, duplicate handling and validator result. Do not implement the
idea and do not touch any file except `BACKLOG.md`.
