---
description: Write a durable handoff document for this session
agent: build
---

Write `docs/handoff/<YYYY-MM-DD>-<slug>.md` (slug from the work, lowercase and
hyphenated) so another agent can pick the work up without this conversation.

Collect the facts from the repository first — do not reconstruct them from
memory:

```bash
git rev-parse --abbrev-ref HEAD && git rev-parse --short HEAD
git status --porcelain
uv run python scripts/check_backlog.py --next
cat artifacts/gate/latest/summary.md 2>/dev/null
```

Use these sections, in this order:

```markdown
## Objective
## Requirements
## Decisions
## Work State   (### Completed / ### Active / ### Blocked)
## Next Move
## Relevant Files
## Important Context
```

Rules for the body:

- **Facts, with provenance.** Branch, HEAD, dirty paths, gate verdict, backlog
  ids and commit subjects are quoted from a command run in this session.
- **Paths, not descriptions.** Name files as `agent/dlp/presidio.py`, and invent
  none: every path must exist in `git ls-files`.
- **No credentials.** Reference `settings.py` fields instead of `.env` values;
  see the `secrets` skill.
- **State what is unfinished.** An unticked acceptance box, an uncommitted file
  and a red gate are the most valuable lines in the document.
- An empty section is `- (none)`, never omitted.

Then report the path you wrote and a two-line summary of where the work stands.
