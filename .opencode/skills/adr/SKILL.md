---
name: ADR workflow
description: Create, change, supersede or validate an architectural decision record in docs/adr/. Use when a decision changes, a new component, protocol, storage or security invariant is chosen, an ADR drifted from the code, or scripts/check_adrs.py fails.
---

# ADR workflow — Creating, Changing and Retiring ADRs

Instructions for working with the Architectural Decision Records in `docs/adr/`.

---

## When to use

- Recording a new architectural decision (new component, protocol, storage,
  security invariant, deployment model).
- Correcting an ADR whose text has drifted from the implementation.
- Superseding or removing a decision.
- Validating the ADR set before a commit (`scripts/check_adrs.py`).

Do **not** use an ADR for routine changes that do not alter a decision: bug
fixes, refactors that preserve behaviour, dependency bumps, or roadmap wishes
(those belong in `backlog/items/`).

---

## File format (authoritative)

One file per decision: `docs/adr/ADR-XXX.md`, three-digit, continuous numbering.

```markdown
# ADR-XXX: <Title>

**Status:** Accepted
**Date:** YYYY-MM-DD
**Last modified:** YYYY-MM-DD

## Context

<Paragraph 1: the problem and why it matters.>

<Paragraph 2: constraints, deployment reality, trade-offs.>

## Decision

1. **<Decision point>**: <concrete technical detail, file/route/table names.>
2. **<Decision point>**: <...>

## Consequences

- **Pros**: <benefit>, <benefit>, <benefit>
- **Cons**: <drawback>, <drawback>, <drawback>
```

Rules enforced by the validator:

| Field / section | Requirement |
|---|---|
| Filename | `ADR-001.md` … `ADR-999.md`, no gaps |
| Title | first line is `# ADR-XXX: <Title>` |
| `Status` | `Proposed`, `Accepted`, `Superseded` or `Deprecated` |
| `Date`, `Last modified` | ISO `YYYY-MM-DD` |
| `## Context` | at least two paragraphs |
| `## Decision` | numbered list starting at `1.` |
| `## Consequences` | `**Pros**` and `**Cons**` bullets |
| Content | no absolute machine-local paths, no credentials |

---

## Procedure

1. **Pick the number.** Read `docs/adr/ADR-Index.md`; the next free number is
   `max + 1` (never reuse a retired number).
2. **Write the file** at `docs/adr/ADR-XXX.md` using the format above.
   - Describe what the system *does*, not what it might do later. If something
     is planned but unbuilt, say so explicitly and name the phase.
   - Reference real artefacts: module paths, table names, Compose services,
     endpoints, environment variables.
3. **Update the index** `docs/adr/ADR-Index.md`: add the row
   `| XXX | <Title> | <Status> |` in numeric order. The index contains the
   table and the process guide only — never embed an ADR body in it.
4. **Validate**:

   ```bash
   uv run python scripts/check_adrs.py
   ```

   It checks structure, numbering, index coverage, statuses, dates, paragraph
   count and path hygiene. Fix everything before committing.
5. **Commit** the ADR and the index together:
   `ADR-XXX: <one-sentence summary of the decision>`.

---

## Changing an existing decision

- **Implementation moved, decision unchanged**: update the ADR text to match
  reality and bump `**Last modified:**`. A wrong ADR is worse than no ADR.
- **Decision changed**: write a new ADR, set the old one to `Superseded`, and
  cross-reference both. Do not rewrite history in a superseded ADR.
- **Decision withdrawn**: set `Deprecated` (keep the file) or delete the file
  and its index row — never leave an index row without a file.

---

## Pitfalls

1. **Do not add skill frontmatter** (`name:`, `description:`, `platforms:`,
   `related_skills:`). Those belong to agent skills, not ADRs. ADRs start with
   `# ADR-XXX:` and use the `**Status:**` block.
2. **Do not paste the ADR body into `ADR-Index.md`.** The index is a table plus
   process guidance.
3. **Do not claim guarantees the code does not provide.** If an ADR says
   "append-only", the database must enforce it; otherwise write "planned" and
   name the phase.
4. **Do not use absolute paths** such as `/home/<user>/...`; use repository
   relative paths (`docs/adr/...`, `db/models.py`).
5. **Do not leave gaps or duplicate numbers**; the validator rejects them.
6. **Do not forget `Last modified`** when editing an accepted ADR.
7. **Do not record secrets, tokens, keys or customer data** in an ADR.
8. **Do not restate the roadmap in every ADR**; link phases to `ADR-008`
   instead of duplicating the version plan.

---

## Checklist before committing

- [ ] `uv run python scripts/check_adrs.py` prints `OK`
- [ ] Context has two substantive paragraphs (problem + constraints)
- [ ] Each numbered decision names exact artefacts
- [ ] Pros/Cons are specific, not marketing
- [ ] Index row added/removed, numbering continuous
- [ ] `Last modified` updated on edited ADRs
- [ ] No machine-local paths, no credentials
- [ ] ADR and index committed together
