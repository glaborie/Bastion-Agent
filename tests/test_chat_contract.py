"""Pure contract tests for the chat request schema and session derivation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent.routing.client import ChatCompletion
from gateway.routers.chat import (
    MAX_MESSAGE_CHARS,
    MAX_MESSAGES,
    ChatRequest,
    _completion_attributes,
    _vault_session,
)

ROOT = Path(__file__).resolve().parent.parent


def test_completion_attributes_split_provider_and_drop_unset_values() -> None:
    """OpenLit reads gen_ai.* for model, tokens and cost; wrong keys are silent.

    OmniRoute answers ``openai/gpt-4o-mini``; the price table is keyed on the
    bare id, so the provider prefix belongs in ``gen_ai.system`` instead. A
    ``None`` token count must be omitted rather than exported as null.
    """
    cloud = _completion_attributes(
        ChatCompletion(
            content="hi",
            model="openai/gpt-4o-mini",
            finish_reason="stop",
            prompt_tokens=263,
            completion_tokens=76,
            total_tokens=339,
            cost_usd=0.0000851,
        ),
        requested="openai/gpt-4o-mini",
    )
    assert cloud["gen_ai.system"] == "openai"
    assert cloud["gen_ai.response.model"] == "gpt-4o-mini"
    assert cloud["gen_ai.response.finish_reasons"] == ["stop"]
    assert cloud["gen_ai.usage.input_tokens"] == 263
    assert cloud["gen_ai.usage.output_tokens"] == 76
    assert cloud["gen_ai.usage.cost"] == pytest.approx(0.0000851)
    assert cloud["bastion.model.swapped"] is False

    local = _completion_attributes(
        ChatCompletion(content="hi", model="qwen2.5-7b-q4_k_m"),
        requested="qwen2.5-7b-q4_k_m",
    )
    assert local["gen_ai.system"] == "local"
    assert local["gen_ai.response.model"] == "qwen2.5-7b-q4_k_m"
    assert "gen_ai.usage.input_tokens" not in local
    assert "gen_ai.response.finish_reasons" not in local
    assert local["bastion.model.swapped"] is False


def test_failover_to_another_model_is_marked_not_hidden() -> None:
    """cloud-primary falls back to a second model; the trace must say so."""
    attributes = _completion_attributes(
        ChatCompletion(content="hi", model="openai/gpt-4o-mini"),
        requested="openai/claude-haiku-4.5",
    )
    assert attributes["bastion.model.swapped"] is True


def test_vault_sessions_are_actor_scoped() -> None:
    """Reusing another caller's conversation id must not share the vault."""
    assert _vault_session("acme", "alice", "conv-1") != _vault_session("acme", "bob", "conv-1")
    assert _vault_session("acme", "alice", "conv-1") == _vault_session("acme", "alice", "conv-1")
    assert _vault_session("acme", "alice", "conv-1") != _vault_session("globex", "alice", "conv-1")


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ChatRequest.model_validate(
            {"messages": [{"role": "user", "content": "hi", "injected": True}]}
        )


def test_unknown_roles_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ChatRequest.model_validate({"messages": [{"role": "root", "content": "hi"}]})


def test_message_and_conversation_limits_are_enforced() -> None:
    with pytest.raises(ValidationError):
        ChatRequest.model_validate(
            {"messages": [{"role": "user", "content": "x" * (MAX_MESSAGE_CHARS + 1)}]}
        )
    with pytest.raises(ValidationError):
        ChatRequest.model_validate(
            {
                "conversation_id": "bad id with spaces",
                "messages": [{"role": "user", "content": "hi"}],
            }
        )
    with pytest.raises(ValidationError):
        ChatRequest.model_validate(
            {"messages": [{"role": "user", "content": "hi"}] * (MAX_MESSAGES + 1)}
        )


def test_empty_conversation_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ChatRequest.model_validate({"messages": []})


def test_dashboard_chat_client_handles_a_blocked_answer() -> None:
    """A blocked notice must be shown, not appended to the resent history."""
    script = (ROOT / "gateway" / "dashboard" / "static" / "chat.js").read_text(encoding="utf-8")
    assert "data.blocked" in script
    assert "history = [];" in script
    assert "Prompt injection detected" in script
