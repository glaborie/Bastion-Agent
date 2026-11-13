### IDEA-035: Share session-scoped Redis key derivation between the vault and the egress sanitizer

- status: inbox
- priority: P3
- phase: v0.3
- area: db
- tags: redis, multi-tenancy, duplication, vault, egress
- depends-on: -
- spec: ADR-015
- created: 2026-11-12
- updated: 2026-11-12
- source: review of agent/dlp/vault.py and agent/egress/sanitizer.py

**Problem**

Both Redis-key writers carry their own copy of the same session-id grammar.
`agent/dlp/vault.py` declares `_MAX_SESSION_ID_LENGTH = 256` at line 46, validates
in `_validate_session` (lines 230-234), and digests with
`hashlib.sha256(session_id.encode("utf-8"))` in `_keys` (line 184);
`agent/egress/sanitizer.py` declares the same 256 at line 48, repeats the same
two error messages and the same digest in `_key` (lines 284-291). ADR-015
decision 2 fixes both key shapes on one session digest, so the two copies must
stay identical, yet nothing links them: changing the limit or the error text in
one file silently changes the accepted session population of half the stack, and
a test for the vault's 256 rule proves nothing about the sanitizer's.

**Outcome**

One shared function in `db/redis.py` validates a session id and returns its
SHA-256 hex digest; `TokenVault._keys` and `EgressSanitizer._key` call it, so the
length limit, the error text and the digest exist once. Both subsystems derive
the identical digest for the same session id, 256 and 257 characters are
accepted and rejected respectively by both, and ADR-015 decision 2 remains the
single description of the key grammar.

**Acceptance**

- [ ] A unit test covers a 256-character and a 257-character session id and asserts the vault and the sanitizer accept the first, reject the second with the shared error text, and derive the same digest for the same session id
- [ ] `uv run pytest tests/test_vault.py tests/test_egress_sanitizer.py -q` passes
- [ ] `grep -rn "_MAX_SESSION_ID_LENGTH" --include=*.py agent/ db/ gateway/` returns exactly one definition, in the shared helper
- [ ] `uv run mypy agent/dlp/vault.py agent/egress/sanitizer.py db/redis.py` is clean

**Notes**

- Tests recompute the digest too: `tests/test_egress_redis.py:48` builds the `egress:<tenant>:<kind>:<digest>` key by hand. Switching that helper to the shared function is enough and keeps the test independent of a private method.
- Out of scope: `gateway/routers/chat.py:177` produces the *session id* (`chat:<digest>` of tenant, actor and conversation), which is then fed to both subsystems. This item only deduplicates what the two consumers do with an id they are handed.
- `priority: P3` because nothing is broken today; the drift is a latent correctness risk rather than a current phase obligation.
