### IDEA-038: Move canonical hashing and approval-token primitives out of db/models.py

- status: done
- priority: P3
- phase: v0.3
- area: db
- tags: audit, models, hashing, refactor
- depends-on: -
- spec: ADR-005
- created: 2026-11-12
- updated: 2026-11-13
- source: review of db/models.py size and import graph, 2026-11-12

**Problem**

`db/models.py` is 738 lines and carries four unrelated jobs: the SQLAlchemy ORM
tables, canonical timestamp/payload serialisation, SHA-256 chain hashing plus
approval-token HMAC signing and verification, and the migration DDL constants
(`TENANT_SCOPE_DDL` and the `DDL` event listeners). Because the pure functions
live among the table definitions, 30 modules import `db.models` for a helper
rather than for a model, so the model file is the de-facto utility module: any
edit to a column drags the whole import surface into review, and the primitives
cannot be reused or tested without loading SQLAlchemy metadata.

**Outcome**

The pure primitives move to `db/hashing.py` (`canonical_timestamp`,
`canonical_payload_bytes`, `hash_payload`, `compute_record_hash`) and
`db/tokens.py` (`fingerprint_request`, `sign_approval_token`,
`hash_approval_token`, `verify_approval_token`). `db/models.py` keeps the ORM
models and DDL and re-exports the moved names, so every existing
`from db.models import ...` keeps working and ADR-005's reference to
`db.models.compute_record_hash` stays valid. No behaviour change and no schema
change.

**Acceptance**

- [x] `db/hashing.py` and `db/tokens.py` exist, and `python -c "from db.models import compute_record_hash, sign_approval_token, canonical_timestamp"` succeeds; `grep -c "^def compute_record_hash" db/models.py` reports 0 and `grep -rc "^def compute_record_hash" db/hashing.py` reports 1
- [x] `wc -l db/models.py` reports fewer than 620 lines (down from 738); the ORM classes and the DDL strings are unchanged apart from imports and re-exports
- [x] `uv run pytest tests/test_audit_chain.py tests/test_approvals.py tests/test_payload_escrow.py -q` passes with no test-file edits
- [x] `uv run --no-sync ruff check .`, `uv run --no-sync ruff format --check .` and `uv run --no-sync mypy settings.py logging_setup.py db gateway agent scripts` are clean
- [x] `docs/adr/ADR-005.md` decision 2 names `db/hashing.py` as the definition site while the re-export keeps `db.models.compute_record_hash` importable

**Notes**

- Measured, not assumed: the primitive blocks are lines 170-244 and 465-530, about 140 lines in total, so the 450-line target suggested at capture is not reachable by moving only pure functions — the remaining ORM plus enums plus DDL is roughly 600 lines. The box is set at 620 accordingly; if a reviewer wants a smaller file, that is a second item about splitting the ORM modules (approvals, escrow, ledger), not a reason to move more than primitives here.
- `utcnow` is a clock rather than a hashing primitive and is kept where it is unless the worker's monkeypatching tests say otherwise; do not widen the move for symmetry.
- `fingerprint_request` is included in `db/tokens.py` because it is `hash_payload` over the invocation dict and only the approval path uses it.
- Deduplication: no open or done item covers module layout — IDEA-004 (export), IDEA-021 (WORM anchor), IDEA-016/029 (escrow) all change ledger behaviour, and IDEA-030/ADR-018 consume the approval token without moving it.
- Implemented 2026-11-13: `db/models.py` is 615 lines. The re-export uses redundant aliases (`from db.hashing import hash_payload as hash_payload`) because mypy strict sets `no_implicit_reexport`; a scoped `pylint: disable=useless-import-alias,unused-import` covers the idiom. An `__all__` list also satisfies mypy and ruff but costs 26 lines and pushed the file to 641, over the 620 box. `_HASH_HEX_LENGTH` now aliases `db.hashing.HASH_HEX_LENGTH`, and `utcnow` kept its body under a `Clock` heading. `db/__init__.py` still imports the primitives from `db.models`, so the public surface is unchanged.
