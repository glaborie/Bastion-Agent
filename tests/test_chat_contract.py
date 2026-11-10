"""Pure contract tests for the chat request schema and session derivation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gateway.routers.chat import (
    MAX_MESSAGE_CHARS,
    MAX_MESSAGES,
    ChatRequest,
    _vault_session,
)


def test_vault_sessions_are_actor_scoped() -> None:
    """Reusing another caller's conversation id must not share the vault."""
    assert _vault_session("alice", "conv-1") != _vault_session("bob", "conv-1")
    assert _vault_session("alice", "conv-1") == _vault_session("alice", "conv-1")


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
