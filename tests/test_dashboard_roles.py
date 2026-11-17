"""Role matrix over the dashboard and its APIs (ADR-007 decision 9, IDEA-068).

The shared app fixture and helpers live in ``tests/test_dashboard.py``; these
tests are the matrix itself, kept apart so the matrix reads as one table.
"""

# pylint: disable=redefined-outer-name  # pytest fixtures

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from gateway.auth.oidc import Principal
from tests.conftest import requires_database
from tests.test_dashboard import (
    ADMIN,
    BOB,
    CAROL,
    DAVE,
    build_ticket,
    dashboard_app,
    seed_ticket,
    session_context,
)

pytestmark = [pytest.mark.integration, requires_database]


@pytest_asyncio.fixture
async def api(
    db_engine: AsyncEngine,
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, Any]]]:
    # pylint: disable=contextmanager-generator-missing-cleanup  # astroid misreads async with
    async with dashboard_app(db_engine) as pair:
        yield pair


# -- the role matrix (ADR-007 decision 9) -----------------------------------
#: ``(method, path, expected status per role)``. Every route added to the
#: dashboard or its APIs belongs here, which is what makes a new surface without
#: a role decision fail the suite.
ROLE_MATRIX: tuple[tuple[str, str, dict[str, int]], ...] = (
    ("GET", "/dashboard", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200}),
    ("GET", "/dashboard/audit", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200}),
    (
        "GET",
        "/dashboard/sessions/conv-matrix",
        {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200},
    ),
    ("GET", "/api/audit", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200}),
    ("POST", "/api/audit/verify", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200}),
    ("GET", "/api/incidents", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200}),
    ("GET", "/api/approvals", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200}),
    ("GET", "/api/evals/latest", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 200}),
    ("GET", "/api/handoffs", {"admin": 200, "operator": 200, "analyst": 403, "readonly": 403}),
    ("GET", "/dashboard/chat", {"admin": 200, "operator": 200, "analyst": 200, "readonly": 403}),
    ("GET", "/dashboard/demo", {"admin": 200, "operator": 200, "analyst": 403, "readonly": 403}),
    # A missing ticket: readable roles get the four-eyes path, the rest never do.
    (
        "POST",
        "/api/approvals/00000000-0000-0000-0000-000000000000/action",
        {"admin": 404, "operator": 404, "analyst": 403, "readonly": 403},
    ),
)

MATRIX_PRINCIPALS = {"admin": ADMIN, "operator": BOB, "analyst": CAROL, "readonly": DAVE}


@pytest.mark.parametrize(("method", "path", "expected"), ROLE_MATRIX)
async def test_the_role_matrix_is_enforced_server_side(
    api: tuple[httpx.AsyncClient, Any],
    method: str,
    path: str,
    expected: dict[str, int],
) -> None:
    client, state = api
    for role, status in expected.items():
        state["context"] = session_context(MATRIX_PRINCIPALS[role])
        response = await client.request(
            method,
            path,
            data={"action": "approve"} if path.endswith("/action") else None,
            headers={"X-CSRF-Token": "csrf-token"},
            follow_redirects=False,
        )
        assert response.status_code == status, (role, method, path, response.text[:200])


@pytest.mark.parametrize("principal", [CAROL, DAVE])
async def test_the_dashboard_renders_no_control_a_viewer_would_be_refused(
    api: tuple[httpx.AsyncClient, Any], principal: Principal, db_engine: AsyncEngine
) -> None:
    """A rendered button that answers 403 is a broken page, not a permission."""
    client, state = api
    await seed_ticket(db_engine, build_ticket())
    state["context"] = session_context(principal)

    page = await client.get("/dashboard")

    assert page.status_code == 200
    assert 'hx-post="/api/approvals/' not in page.text
    assert 'id="handoff-slot"' not in page.text
    assert 'href="/dashboard/demo"' not in page.text


async def test_a_readonly_session_sees_no_chat_link_while_an_analyst_does(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, state = api

    state["context"] = session_context(CAROL)
    analyst_page = await client.get("/dashboard")
    assert 'href="/dashboard/chat"' in analyst_page.text

    state["context"] = session_context(DAVE)
    viewer_page = await client.get("/dashboard")
    assert 'href="/dashboard/chat"' not in viewer_page.text


@pytest.mark.parametrize("principal", [CAROL, DAVE])
async def test_a_viewer_cannot_start_a_demo_run(
    api: tuple[httpx.AsyncClient, dict[str, Any]], principal: Principal
) -> None:
    """The demo console starts write scenarios, so the POST stays operator/admin."""
    client, state = api
    state["context"] = session_context(principal)

    response = await client.post(
        "/dashboard/demo/runs",
        data={"scenario_id": "guarded-tool"},
        headers={"X-CSRF-Token": "csrf-token"},
    )

    assert response.status_code == 403
