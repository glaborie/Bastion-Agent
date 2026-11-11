---
name: Secrets hygiene
description: Inspect configuration and quote command output without putting credentials into the transcript. Use before any command that could print a key, password or token (.env, printenv, docker inspect), when a credential appears in output, or when a secret needs rotating.
---

# Secrets hygiene

A credential that reaches the transcript is in a session export, a compaction
summary, a tool-output file and possibly a memory. The target is: read what you
need, leave the value where it lives.

## Read configuration through settings

```bash
uv run python -c "import settings; print(settings.get_settings().redacted_database_url)"
uv run python -c "import settings; s=settings.get_settings(); print(s.dlp_entities, s.classifier_injection_profile)"
```

`settings.py` exposes the fields you usually want, and `redacted_database_url`
masks the password for you.

## Inventory without disclosure

```bash
grep -oE '^[A-Z][A-Z0-9_]*=' .env          # names only
grep -cE '^[A-Z][A-Z0-9_]*=' .env          # how many are set
```

When you must confirm a value is present, print a prefix and a length and stop
there: `cut -c1-6` plus `wc -c`. A length and prefix answer "is it set and
plausible" without handing the value to the model.

Prefer testing a credential by using it — call the API and report the status
code — over comparing its text with an expected string.

## When a credential does land in output

1. Name it: which variable, which file, which provider.
2. Say where the copy now exists: this transcript, `~/.local/share/opencode/tool-output/`, a gate or eval log, a session export.
3. Rotate it at the source, then update the one place that holds it.
4. Quote only a redacted form in every later report (`sk-or-v1-abcd…`).

Rotation surfaces seen in this setup: provider keys in `~/.config/opencode/opencode.json` and `.env` (`OPENROUTER_API_KEY`, Langfuse `sk-lf-…`, freellmapi), Postgres and Redis passwords in `.env`, Keycloak admin credentials in `.env` plus `config/keycloak/realm-export.json`, OmniRoute keys.

## Before sharing anything

`opencode session export --sanitize` produces a redacted transcript; a raw export
carries every value the session saw. Check a backup or report for
`sk-`, `ghp_`, `eyJ` and `password=` before it leaves the machine.

## Done

No new credential value appears in this session's output, and any that did is
named, located and queued for rotation.
