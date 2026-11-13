---
name: Backlog intake
description: Capture a new idea as an item file under backlog/items/ with priority, phase, area, tags, dependencies and acceptance criteria. Use when the user runs /idea, or mentions an idea, improvement, follow-up, "we should", "later", "not now", a review finding being deferred, or an incident follow-up that will not be fixed immediately.
---

# Backlog intake

You add ideas to the item store under `backlog/items/` in the Bastion-Agent
repository. You never implement them, and you never touch anything else.

Each item is one file. `docs/adr/` holds decisions, `HANDOVER_SPEC.md` holds the
design, `backlog/items/` holds what someone wants and nobody has decided yet, and
`BACKLOG.md` is a rendered index of those files that is generated and untracked.
`scripts/check_backlog.py` is the schema enforcement; if it fails, the capture is
not finished.

## Non-negotiables

1. Only the new item file under `backlog/items/` and scratch drafts under
   `/tmp/opencode/backlog-drafts/` may be written. Never edit source code, tests,
   ADRs, config, `AGENTS.md`, `backlog/config.toml`, another item's file, or
   `BACKLOG.md` (rendered and untracked). Drafts are transport, never a source of
   truth and never referenced from the repo.
2. One idea per item, and one item per file. Split compound ideas into separate
   items and say so in the report. When several ideas arrive together, use the
   batch procedure below instead of creating them one after another in a single
   writer.
3. Do not ask the user anything: you run as a subagent with no user turn. When
   something is unclear, choose the conservative classification and record the
   open question in a final `**Notes**` section.
4. Never create an item for something already shipped or already decided. Check
   `docs/adr/*.md` first; an Accepted ADR whose behaviour exists in the tree is
   not an idea.
5. Never renumber, reorder or rewrite existing items. The only allowed edit to an
   existing item is a `**Notes**` line and its `- updated:` date.

## Procedure

1. Read the item files under `backlog/items/`, then run
   `uv run python scripts/check_backlog.py --next` to see current state.
2. Deduplicate. Search the backlog for the same problem, not the same words
   (grep the proposed keywords and the module name). Also scan `docs/adr/` for a
   decision that already covers it.
   - Same problem exists: do not create an item. Append under that item's
     `**Notes**`:
     `- <YYYY-MM-DD>: <one line on the new angle, source>`. Bump `- updated:`.
   - Covered by an Accepted ADR and already built: report "already decided" and
     stop.
   - Covered by an ADR but not built: create the item with `spec: ADR-NNN`.
3. Create the file. The script allocates the next free id from the highest
   existing one and creates the path exclusively, so it can never overwrite
   another capture:

   ```bash
   uv run python scripts/check_backlog.py --new "<imperative title>"
   # -> backlog/items/IDEA-NNN-<slug>.md
   ```

   If it reports that the path already exists, retry: another capture took that
   id. Never pick an id by hand, and never reuse a dropped item's id.
4. Fill the skeleton in: `priority`, `phase`, `area`, `tags`, `depends-on`,
   `spec`, `source`, then `**Problem**`, `**Outcome**` and `**Acceptance**`. Every
   `TODO: fill` must be gone; the validator rejects them.
5. Run `uv run python scripts/check_backlog.py --check`. Fix every error it
   reports; do not leave warnings unexplained in your report. `--write` also
   validates and additionally refreshes the local, untracked `BACKLOG.md` index.
6. Report one short paragraph: id, title, `priority/phase/area`, tags, whether a
   duplicate was merged, and the validator result.

## Batch capture

When a turn captures more than one idea, drafting is parallel and file creation
is single-threaded, so two drafters cannot race on the same id.

1. List every idea and a slug for each before drafting. If two ideas are the same
   problem, merge them here, not later.
2. Spawn one drafter per idea. Each drafter reads this skill, deduplicates, and
   writes exactly one file to `/tmp/opencode/backlog-drafts/<slug>.md`, shaped
   like a normal item but with `### IDEA-000: <title>` as the heading. `IDEA-000`
   is a placeholder; the merger renumbers.
3. The drafter must not touch `backlog/items/`, must not run
   `check_backlog.py --new`, and must not allocate an id — concurrent drafters
   would all pick the same one. If a drafter cannot write files (for example it
   runs under a read-only agent profile), it returns the draft in its reply and
   the merger saves it; never treat the missing file as a failed idea.
4. Run the drafters concurrently; completion order is irrelevant.
5. Merge serially, in the order the ideas were requested. For each draft: run
   `--new "<title>"`, replace the skeleton's body with the draft's, keep the id
   the script printed, then move on. Do not run `--check` between items.
6. After the last merge, run `check_backlog.py --check` once. Fix the offending
   item and re-run if it fails; a later clean run does not excuse an earlier
   broken item.
7. Delete the draft files after the validator passes, and report every id in one
   summary. Name any idea whose draft was lost rather than silently dropping it.

Batch mode relaxes nothing else: ids stay unique and are never reused, every
item keeps its `**Problem**`, `**Outcome**` and an executable acceptance box,
deduplication still happens before an id is allocated, and no draft may contain
a secret, customer data, an internal hostname or an absolute machine path. The
`/tmp` location is transport, not content.

## Rubrics

`status` on capture is always `inbox`. Triage into `ready` is a human decision;
never write `ready`, `active`, `done` or `blocked` yourself.

`priority`:

- `P0` breaks a stated security invariant or blocks the current phase from
  running (leak, bypass, corrupt ledger, stack that will not start).
- `P1` required for the current phase's definition of done in ADR-008.
- `P2` next phase, or a real gap that can wait one phase. Use this when unsure.
- `P3` nice to have, no phase commitment.

`phase` is one of `v0.1`..`v0.6` from ADR-008. A defect in shipped behaviour
belongs to the current phase; new capability belongs to the phase whose scope in
ADR-008 names it; a fix with no obvious home is the current phase.

`area` is exactly one of:

| area | covers |
|---|---|
| `agent` | `agent/` - dlp, routing, egress, tools, runtime |
| `gateway` | `gateway/` - routers, dashboard, auth, approvals |
| `db` | `db/` - models, session, audit ledger, redis keys |
| `infra` | compose, Dockerfile, `config/`, `.env.example`, CI workflows |
| `security` | cross-cutting invariants: canaries, RBAC, secrets, threat model |
| `evals` | golden corpus, DeepEval gates, `scripts/run_evals.py` |
| `docs` | README, DEMO, COMPLIANCE, HANDOVER_SPEC, ADRs |
| `tooling` | `scripts/`, repo automation, the backlog machinery itself |

`tags` are 1-5 lowercase kebab-case words: technology plus concern
(`redis`, `gpu`, `canary`, `latency`, `multi-tenancy`). Reuse tags already in
the file instead of inventing synonyms.

`depends-on` is `-` unless the item is genuinely unbuildable before another item
completes. Then list ids, comma-separated. Do not model "related to".

`spec` is the ADR that governs the change (`ADR-012`), `ADR-Index`,
`HANDOVER_SPEC`, or `-` when nothing governs it yet. If the right answer is "we
have no decision", say so in **Notes** rather than forcing a reference.

## Item format

`--new` writes this skeleton; fill it in without changing the field order, and
keep the heading as the first line of the file (the validator and the filename
both depend on it):

```markdown
### IDEA-NNN: <imperative title, no trailing period>

- status: inbox
- priority: P2
- phase: v0.2
- area: agent
- tags: redis, latency
- depends-on: -
- spec: ADR-008
- created: YYYY-MM-DD
- updated: YYYY-MM-DD
- source: <session, review of X, incident Y, ADR-008 phase scope>

**Problem**

<2-4 sentences. The concrete gap today, naming the file, endpoint, config key or
measured number. Not a wish.>

**Outcome**

<What is true and verifiable once this is done.>

**Acceptance**

- [ ] <command or test that proves it>
- [ ] <doc or ADR that must change with it>
```

The file is named `IDEA-NNN-<slug>.md`, where the slug is the title lowercased
and hyphenated. `**Acceptance**` needs at least one checkbox that can be
executed. "Works better" is not acceptance. A `**Notes**` section, when needed,
goes at the very end.

## What does not belong

- Work you could start immediately and finish in the same turn as the idea.
- Restatements of an Accepted ADR.
- Vague aspirations with no observable outcome ("improve the dashboard").
- Secrets, customer data, internal hostnames, absolute machine paths.
- Multi-phase epics. Capture the first concrete step; note the rest in
  **Notes**.
