"""Authentication dependency and RBAC tests (ADR-003)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context, require_csrf, require_roles
from gateway.auth.roles import any_satisfied, is_satisfied, normalise_roles
from gateway.auth.session import SessionRecord

ALICE = Principal(subject="alice-sub", username="alice", roles=frozenset({"operator"}))
BOB = Principal(subject="bob-sub", username="bob", roles=frozenset({"operator", "analyst"}))
CAROL = Principal(subject="carol-sub", username="carol", roles=frozenset({"analyst"}))
ROOT = Principal(subject="root-sub", username="root", roles=frozenset({"admin"}))


def _session(principal: Principal, csrf_token: str = "csrf-token") -> SessionRecord:
    now = datetime.now(UTC)
    return SessionRecord(
        session_id="session-1",
        principal=principal,
        access_token="access-token",
        csrf_token=csrf_token,
        created_at=now,
        access_expires_at=now + timedelta(minutes=5),
        last_seen_at=now,
    )


def _app_with_context(context: AuthContext | None) -> FastAPI:
    app = FastAPI()

    @app.get("/protected")
    async def protected(
        active: AuthContext = Depends(require_roles("operator", "admin")),
    ) -> dict[str, Any]:
        return {"subject": active.principal.subject, "method": active.method}

    @app.post("/mutate")
    async def mutate(active: AuthContext = Depends(require_csrf)) -> dict[str, Any]:
        return {"method": active.method, "subject": active.principal.subject}

    if context is None:
        app.dependency_overrides[get_auth_context] = _unauthorized
    else:
        app.dependency_overrides[get_auth_context] = lambda: context
    return app


def _unauthorized() -> AuthContext:
    raise HTTPException(
        status_code=401,
        detail="authentication required",
        headers={"WWW-Authenticate": 'Bearer realm="bastion"'},
    )


def test_admin_is_a_superset_but_other_roles_are_independent() -> None:
    assert is_satisfied(ROOT.roles, "operator")
    assert is_satisfied(ROOT.roles, "readonly")
    assert is_satisfied(BOB.roles, "analyst")
    assert not is_satisfied(BOB.roles, "admin")
    assert not is_satisfied(CAROL.roles, "operator")
    assert any_satisfied(CAROL.roles, ("operator", "analyst"))


def test_unknown_roles_are_dropped_from_claims() -> None:
    assert normalise_roles(["operator", "OPERATOR", "offline_access", 42]) == frozenset(
        {"operator"}
    )


def test_require_roles_rejects_unknown_roles_at_definition_time() -> None:
    with pytest.raises(ValueError, match="unknown role"):
        require_roles("superuser")
    with pytest.raises(ValueError, match="at least one"):
        require_roles()


def test_operator_can_reach_an_operator_route() -> None:
    client = TestClient(_app_with_context(AuthContext(principal=ALICE, method="bearer")))
    response = client.get("/protected")
    assert response.status_code == 200
    assert response.json()["subject"] == "alice-sub"


def test_analyst_is_forbidden_on_an_operator_route() -> None:
    client = TestClient(_app_with_context(AuthContext(principal=CAROL, method="bearer")))
    response = client.get("/protected")
    assert response.status_code == 403
    assert response.json()["detail"] == "insufficient role"


def test_admin_satisfies_any_required_role() -> None:
    client = TestClient(_app_with_context(AuthContext(principal=ROOT, method="bearer")))
    assert client.get("/protected").status_code == 200


def test_missing_credentials_are_401_with_www_authenticate() -> None:
    client = TestClient(_app_with_context(None))
    response = client.get("/protected")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer realm="bastion"'


def test_session_authentication_requires_a_matching_csrf_token() -> None:
    context = AuthContext(principal=BOB, method="session", session=_session(BOB))
    client = TestClient(_app_with_context(context))

    assert client.post("/mutate").status_code == 403
    assert client.post("/mutate", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post("/mutate", headers={"X-CSRF-Token": "csrf-token"}).status_code == 200


def test_csrf_token_can_arrive_in_the_form_body() -> None:
    context = AuthContext(principal=BOB, method="session", session=_session(BOB))
    client = TestClient(_app_with_context(context))
    response = client.post("/mutate", data={"csrf_token": "csrf-token"})
    assert response.status_code == 200


def test_cross_origin_session_mutation_is_rejected() -> None:
    context = AuthContext(principal=BOB, method="session", session=_session(BOB))
    client = TestClient(_app_with_context(context))
    response = client.post(
        "/mutate",
        headers={"X-CSRF-Token": "csrf-token", "Origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_loopback_host_aliases_are_treated_as_same_origin() -> None:
    # Windows/WSL or Docker Desktop may rewrite localhost <-> 127.0.0.1 between
    # the browser and the gateway; both are the same machine.
    context = AuthContext(principal=BOB, method="session", session=_session(BOB))
    client = TestClient(_app_with_context(context), base_url="http://127.0.0.1:8000")
    response = client.post(
        "/mutate",
        headers={"X-CSRF-Token": "csrf-token", "Origin": "http://localhost:8000"},
    )
    assert response.status_code == 200


def test_opaque_origin_null_is_allowed_only_with_a_valid_csrf_token() -> None:
    # An embedded/sandboxed browser view sends "Origin: null". The CSRF token
    # remains the control; without it the request is still rejected.
    context = AuthContext(principal=BOB, method="session", session=_session(BOB))
    client = TestClient(_app_with_context(context))

    assert client.post("/mutate", headers={"Origin": "null"}).status_code == 403
    assert (
        client.post("/mutate", headers={"Origin": "null", "X-CSRF-Token": "csrf-token"}).status_code
        == 200
    )


def test_bearer_mutations_are_exempt_from_csrf() -> None:
    client = TestClient(_app_with_context(AuthContext(principal=BOB, method="bearer")))
    response = client.post("/mutate", headers={"Origin": "http://evil.example"})
    assert response.status_code == 200
