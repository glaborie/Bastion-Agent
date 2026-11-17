"""The dashboard handoff surface: template, wiring and notification contract.

The browser Notification API cannot be driven from pytest, so what is pinned
here is the contract around it: who sees the panel, what the fragment carries,
and that the script notifies from those attributes alone — never from text.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.auth.oidc import Principal
from gateway.dashboard.templating import templates

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "gateway" / "dashboard" / "templates" / "base.html"
SCRIPT = ROOT / "gateway" / "dashboard" / "static" / "handoffs.js"

OPERATOR = Principal(
    subject="alice-sub", tenant_id="acme", username="alice", roles=frozenset({"operator"})
)
ADMIN = Principal(
    subject="break-sub", tenant_id="acme", username="breakglass", roles=frozenset({"admin"})
)
ANALYST = Principal(
    subject="carol-sub", tenant_id="acme", username="carol", roles=frozenset({"analyst"})
)
READONLY = Principal(
    subject="dave-sub", tenant_id="acme", username="dave", roles=frozenset({"readonly"})
)


def _render_base(principal: Principal | None) -> str:
    request = SimpleNamespace(url=SimpleNamespace(path="/dashboard", query=""))
    return templates.env.get_template("base.html").render(
        request=request, principal=principal, csrf_token="csrf-token", theme="system"
    )


@pytest.mark.parametrize("principal", [OPERATOR, ADMIN])
def test_the_panel_is_wired_for_operator_and_admin(principal: Principal) -> None:
    page = _render_base(principal)

    assert 'id="handoff-slot"' in page
    assert 'hx-get="/api/handoffs/panel"' in page
    assert "every 15s" in page
    assert "/static/handoffs.js" in page
    assert 'href="/dashboard/audit?event_type=HANDOFF_REQUIRED"' in page


@pytest.mark.parametrize("principal", [ANALYST, READONLY, None])
def test_no_panel_and_no_script_for_other_principals(principal: Principal | None) -> None:
    page = _render_base(principal)

    # The script is loaded on every page but returns before touching anything
    # when there is no slot; the missing panel, not the script, is the fence.
    assert 'id="handoff-slot"' not in page


def test_the_fragment_carries_metadata_attributes_only() -> None:
    row = SimpleNamespace(
        session_id="6fb2af8453734dfd97025541ab9196ed",
        timestamp=datetime(2026, 11, 17, 13, 47, 46, tzinfo=UTC),
        metadata_json={"verdict": "escalating_language", "markers": 3},
    )

    html = templates.env.get_template("partials/handoff_panel.html").render(handoffs=[row])

    assert 'data-handoff-id="6fb2af8453734dfd97025541ab9196ed"' in html
    assert 'data-handoff-verdict="escalating_language"' in html
    assert "2026-11-17 13:47:46Z" in html
    # Nothing from the conversation itself, and not even the marker count.
    assert "markers" not in html
    assert "escalate me" not in html


def test_an_empty_queue_says_so() -> None:
    html = templates.env.get_template("partials/handoff_panel.html").render(handoffs=[])

    assert "No handoffs queued" in html


def test_the_script_notifies_from_the_attributes_it_renders() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    fragment = (
        ROOT / "gateway" / "dashboard" / "templates" / "partials" / "handoff_panel.html"
    ).read_text(encoding="utf-8")

    for attribute in ("handoffId", "handoffVerdict", "handoffCreated"):
        assert f"dataset.{attribute}" in script
    for attribute in ("data-handoff-id", "data-handoff-verdict", "data-handoff-created"):
        assert attribute in fragment
    # One notification per id, and a first poll that primes rather than fires.
    assert "sessionStorage" in script
    assert "tag:" in script
    assert "Notification.permission" in script
    assert "requestPermission" in script
    # The body is built from the attributes alone; nothing injects markup.
    assert "innerHTML" not in script
    assert "messages" not in script
