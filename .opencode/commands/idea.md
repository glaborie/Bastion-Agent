---
description: Capture an idea as a new backlog item file without implementing it
agent: backlog
subagent: true
---

Capture this idea as a new item under `backlog/items/` following the
`backlog-intake` skill:

$ARGUMENTS

Load the `backlog-intake` skill first. Deduplicate before writing, then create
exactly one item with `uv run python scripts/check_backlog.py --new "<title>"`
(which allocates the next free IDEA-NNN id), fill it in, classify it, and run
`uv run python scripts/check_backlog.py --check`. Report the id, classification,
duplicate handling and validator result. Do not implement the idea, and do not
touch any file except the new item file.
