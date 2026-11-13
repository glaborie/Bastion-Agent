#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/home/glaborie/projects/Bastion-Agent"
OPENCODE_BIN="$HOME/.opencode/bin/opencode"

cd "$PROJECT_DIR"

echo "=== Bastion-Agent Implementation Handover to OpenCode ==="
echo "Target Model: DeepSeek V4 (via openrouter/deepseek/deepseek-chat or configured provider)"
echo "Working Directory: $PROJECT_DIR"
echo ""

if [ ! -x "$OPENCODE_BIN" ]; then
    echo "Error: OpenCode binary not found at $OPENCODE_BIN"
    exit 1
fi

PROMPT="Please read AGENTS.md and HANDOVER_SPEC.md thoroughly. Implement Milestone 1 through Milestone 6 step-by-step: create the complete project scaffold, docker-compose.yml, FastAPI gateway, auth/RBAC, Presidio DLP with AES-256 Redis reversible token vault, ONNX sensitivity routing, tool guards with four-eyes HITL suspension, HTMX Command Control dashboard, egress canary sanitizers, hash-chained audit logging, and the DeepEval golden test suite. Verify code quality and ensure pytest runs cleanly."

echo "Starting OpenCode run..."
"$OPENCODE_BIN" run "$PROMPT" \
    --model "openrouter/deepseek/deepseek-chat" \
    -f "$PROJECT_DIR/AGENTS.md" \
    -f "$PROJECT_DIR/HANDOVER_SPEC.md"
