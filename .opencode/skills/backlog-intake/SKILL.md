---
name: Backlog intake
description: Capture a new idea in BACKLOG.md with priority, phase, area, tags, dependencies and acceptance criteria. Use when the user runs /idea, or mentions an idea, improvement, follow-up, "we should", "later", "not now", a review finding being deferred, or an incident follow-up that will not be fixed immediately.
---

# Backlog intake

You add ideas to `BACKLOG.md` in the Bastion-Agent repository. You never
implement them, and you never touch anything else.

The backlog is append-only. `docs/adr/` holds decisions, `HANDOVER_SPEC.md` holds
the design, `BACKLOG.md` holds what someone wants and nobody has decided yet.
`scripts/check_backlog.py` is the schema enforcement; if it fails, the capture
is not finished.

## Non-negotiables

1. Only `BACKLOG.md` may be written. Never edit source code, tests, ADRs, config,
   `AGENTS.md` or the generated `## Board` / `## Index` sections.
2. One idea per invocation. Split compound ideas into separate items and say so
   in the report.
3. Do not ask the user anything: you run as a subagent with no user turn. When
   something is unclear, choose the conservative classification and record the
   open question in a final `**Notes**` section.
4. Never create an item for something already shipped or already decided. Check
   `docs/adr/*.md` first; an Accepted ADR whose behaviour exists in the tree is
   not an idea.
5. Never renumber, reorder or rewrite existing items. The only allowed edit to an
   existing item is a `**Notes**` line and its `- updated:` date.

## Procedure

1. Read `BACKLOG.md` completely, then run
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
3. Allocate the id: highest existing `IDEA-NNN` plus one, zero-padded to three
   digits. Never reuse an id, including dropped items.
4. Classify with the rubrics below, then append the item at the end of the file
   and bump the `- next-id:` meta line.
5. Run `uv run python scripts/check_backlog.py --write`. Fix every error it
   reports; do not leave warnings unexplained in your report.
6. Report one short paragraph: id, title, `priority/phase/area`, tags, whether a
   duplicate was merged, and the validator result.

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

Append exactly this shape; the validator depends on it:

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

`**Acceptance**` needs at least one checkbox that can be executed. "Works
better" is not acceptance. A `**Notes**` section, when needed, goes at the very
end.

## What does not belong

- Work you could start immediately and finish in the same turn as the idea.
- Restatements of an Accepted ADR.
- Vague aspirations with no observable outcome ("improve the dashboard").
- Secrets, customer data, internal hostnames, absolute machine paths.
- Multi-phase epics. Capture the first concrete step; note the rest in
  **Notes**.
