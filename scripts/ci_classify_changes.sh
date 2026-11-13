#!/usr/bin/env bash
# Classify a pull-request diff for .github/workflows/ci.yml.
#
#   git diff --no-renames --name-only --diff-filter=ACDMT FETCH_HEAD...HEAD \
#     | scripts/ci_classify_changes.sh >> "$GITHUB_OUTPUT"
#
# Prints docs_only, evals, osv, scan and tests as key=value lines. A PR skips a suite
# only when no changed path can affect it, so every rule below is a statement
# about what that suite observes, not about how important the file is.
#
# tests/test_ci_classify.py holds the contract; change a rule here and it fails
# there.
set -euo pipefail

changed=$(cat)

DOCS='(\.md$|^wiki/|\.(png|jpe?g|gif|svg)$)'

# A root-level shell script is neither imported by a test nor executed by CI, so
# a diff that only deletes one cannot move the suite. scripts/ is deliberately
# not exempt: the audit-witness step runs scripts/init_audit_witness.sh and the
# scanner runs the rest, and the test suite proves every script named in the
# workflow still gates it.
TESTS='(\.md$|^wiki/|\.(png|jpe?g|gif|svg)$|^[^/]+\.sh$)'

# The classifier, the two redaction stages it routes for, and the golden corpus
# are the only things the eval gates assert on.
EVALS='^(agent/(routing|dlp|egress)/|tests/data/|tests/test_(classifier|dlp|egress|eval)[^/]*\.py|scripts/(run_evals|check_classifier_dispatch)\.py|settings\.py|pyproject\.toml|models/)'

# Only when the scanner itself moves. Master and the weekly run always scan, so
# a pin bump is verified within a day (ADR-016).
SCAN='^(trivy\.yaml|scripts/(scan_images\.sh|trivy-scan\.sh|image_inventory\.py|aggregate_trivy_reports\.py|check_trivy_report\.py|ci_classify_changes\.sh)|\.github/workflows/ci\.yml)$'

# A PR changing the audited inputs or the gate must receive a fresh OSV verdict.
OSV='^(uv\.lock|pyproject\.toml|scripts/(update_threat_intel\.py|ci_classify_changes\.sh)|tests/test_threat_intel\.py|\.github/workflows/ci\.yml)$'

emit() { printf '%s=%s\n' "$1" "$2"; }

# Every path matches. An empty diff is not "all docs": it falls through to the
# else branch, which runs the suite.
every() { [ -n "$changed" ] && ! grep -qvE "$1" <<<"$changed"; }

# Any path matches.
any() { grep -qE "$1" <<<"$changed"; }

if every "$DOCS"; then emit docs_only true; else emit docs_only false; fi
if every "$TESTS"; then emit tests false; else emit tests true; fi
if any "$EVALS"; then emit evals true; else emit evals false; fi
if [ -z "$changed" ] || any "$OSV"; then emit osv true; else emit osv false; fi
if any "$SCAN"; then emit scan true; else emit scan false; fi
