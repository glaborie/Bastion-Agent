### IDEA-081: Extract one shared .env parser for the env-vault and image-inventory scripts

- status: done
- priority: P2
- phase: v0.5
- area: tooling
- tags: scripts, dotenv, refactor
- depends-on: -
- spec: ADR-016
- created: 2026-11-18
- updated: 2026-11-20
- source: refactoring scan of `scripts/` during the 2026-11-18 session

**Problem**

`scripts/check_env_vault.py:64-84` and `scripts/image_inventory.py:66-89` each carry their own copy of the same Compose-style `.env` reader — `KEY=VALUE`, an optional `export ` prefix, `#` comment lines, surrounding whitespace and one pair of matching quotes — and the copies are not equivalent: `image_inventory` skips a key that does not match `[A-Za-z_][A-Za-z0-9_]*` (`:83-84`) while `check_env_vault` stores it as-is (`:83`). The first reader decides whether a Vault-materialised secret counts as present in the rendered env, and the second decides which tag each image reference resolves to for the Trivy scan set, so a quoting, comment or whitespace fix applied to one copy makes the two answer differently about the same file. Nothing compares the readers, so the disagreement would surface as a gate that passes on one path and fails on the other rather than as a failing test.

**Outcome**

One `read_env(path)` lives in a small importable helper (`scripts/_env.py`), both scripts import it instead of defining their own, and its docstring states the grammar it implements, so the next change to quoting or comment handling is a single edit with a single test. The one existing divergence — the key-shape check above — is resolved deliberately rather than by whichever copy was edited last. For every file shape the repository uses (`.env.example` and its single quoted value at `:78`, `.env.vault` as `make vault-export` writes it, and the comment/blank/whitespace forms) the values returned are unchanged on both call sites, so `--render` precedence and the image scan set are unaffected.

**Acceptance**

- [x] `uv run python scripts/check_env_vault.py --render` still proves precedence (sentinels reach the render with `.env.vault`, disappear without it) and `uv run pytest tests/test_env_vault.py -q` is green, so the gate reads the same values as before
- [x] `uv run python scripts/image_inventory.py --json` resolves the same image references as the pre-change script, and `uv run pytest tests/test_compliance_scan.py -q` — including `test_env_file_supplies_overrides_and_process_env_wins` — is green, so the `--env-file`/process-env precedence is unchanged
- [x] `tests/test_env_parser.py` exercises the shared reader directly: quoted and unquoted values, `export KEY=`, comment and blank lines, surrounding whitespace, an invalid key, and an absent file; it also asserts both scripts return the same mapping for one fixture, so a re-divergence fails the suite
- [x] `grep -rn "def read_env" --include=*.py scripts/` returns exactly one definition, in the helper, and `grep -rn "from scripts._env import read_env" scripts/` returns both call sites
- [x] `scripts/gate.sh` passes — including its `mypy` step over `scripts` and the two ruff steps — with no file changed outside the two scripts, the helper and the new test

**Notes**

- Dedupe: grepped `backlog/items/` for `read_env`, `parser`, `dotenv`, `env.vault`, `check_env_vault` and `image_inventory`. `IDEA-055` (done) edited `image_inventory.py`'s parser, but for overlay/anchor coverage, not for the duplicate; `IDEA-056` and `IDEA-076` (done) are the `.env.vault` consumption and key-set items, and both extend `check_env_vault.py` without touching the reader. No item owns the duplicate reader; nothing was merged.
- Classification: `P2`/`v0.5`/`tooling` as captured. `P2` because neither copy is misreading a committed file today, so this is a maintenance gap that can wait a phase rather than a live failure; `P3` is defensible if triage sees no second reader being added soon. `area: tooling` because every edited file is under `scripts/` plus one test.
- `spec: ADR-016` because decision 1 fixes the `.env`-reading semantics `image_inventory` must preserve (process environment wins over the file, `--no-env-file` makes it reproducible). `ADR-021` decision 5 fixes the `.env.vault` layering that `check_env_vault` proves but says nothing about the parser; `ADR-002` (DLP entities) and `ADR-017` (Falco field allow-list, which excludes `proc.env`) do not govern env rendering. No ADR amendment is required while the documented semantics stay put — touch ADR-016 only if the resolved divergence changes something it states.
- Open question for triage: which side of the key-shape divergence wins. `image_inventory`'s `[A-Za-z_][A-Za-z0-9_]*` check is the Compose-compatible answer and is recommended; `check_env_vault`'s leniency is not observable today because it only looks up a fixed key set.
- Honest limit: this ends the double maintenance, not the grammar's gaps. Both copies keep an inline comment after an unquoted value (`KEY=value # note`) as part of the value, and neither implements full Compose dotenv semantics (multi-line quoted values, escapes). Preserving that is the point of the refactor; a Compose-exact parser is a separate decision.
- `scripts/` has no `__init__.py`, but tests already import `from scripts import check_backlog`, so `from scripts._env import read_env` resolves the same way and no packaging change is needed.
- Scope: intake only. No script, helper, test, document or ADR edit is part of this capture.
- Implementation (2026-11-19): `scripts/__init__.py` had to be added so the literal `from scripts._env import read_env` survives `mypy ... scripts`; without it mypy stops with "Source file found twice under different module names: `_env` and `scripts._env`" and recommends `__init__.py`. That one empty package marker is the only path outside the four criterion 5 names, so its box stays unticked: accept the marker, or re-scope criterion 4 to a bare `_env` import. The key-shape divergence was resolved the recommended way (invalid keys skipped, Compose-compatible). `--render` ran with the main checkout's `.env.vault` symlinked in; `image_inventory --json` was byte-identical to the pre-change script for `docker-compose.yml` and the gpu/pki/vault overlays; gate 14/14 green.
- Decision (2026-11-20): the `scripts/__init__.py` package marker is accepted, so criterion 5 holds with that one extra file and the item closes. The alternative — a bare `_env` import plus a `sys.path` insert — was rejected to keep the package-qualified import the criterion names.
