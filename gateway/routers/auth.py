"""Browser login, callback and logout for the Command Control Center.

The dashboard uses the OIDC authorization-code flow with PKCE. Access and
refresh tokens stay server-side in Redis; the browser only receives an opaque
session id. ``state`` and ``nonce`` are single-use values held in Redis, so a
replayed callback cannot create a session.
"""

from __future__ import annotations

import logging
import secrets
import urllib.parse
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from gateway.auth.oidc import (
    OAuthExchangeError,
    OIDCTokenClient,
    TokenValidationError,
    TokenValidator,
    generate_pkce_pair,
)
from gateway.auth.rbac import (
    AuthContext,
    get_auth_context,
    get_session_manager,
    get_token_client,
    get_token_validator,
    require_csrf,
)
from gateway.auth.session import LoginState, SessionManager, safe_next_path
from gateway.dashboard.templating import render, render_error
from settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_ERROR_DETAILS: dict[str, str] = {
    "access_denied": "Keycloak declined the sign-in request.",
    "invalid_request": "The sign-in response was incomplete.",
    "state_expired": "The sign-in attempt expired or was already used. Start again.",
    "exchange_failed": "Keycloak rejected the authorization code.",
    "id_token_invalid": "The identity token did not validate.",
    "access_token_invalid": "The access token did not validate.",
}


@router.get("/login", include_in_schema=False)
async def login(
    request: Request,
    next_path: str | None = Query(default=None, alias="next", max_length=512),
    token_client: OIDCTokenClient = Depends(get_token_client),
    sessions: SessionManager = Depends(get_session_manager),
) -> RedirectResponse:
    """Start an authorization-code + PKCE login."""
    settings = get_settings()
    # If a logout is still in flight, never silently re-use the SSO session that
    # the end-session redirect is about to terminate.
    prompt = "login" if request.cookies.get(settings.logout_marker_cookie_name) else None
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    pkce = generate_pkce_pair()
    await sessions.store_login_state(
        state,
        LoginState(
            nonce=nonce,
            code_verifier=pkce.verifier,
            next_path=safe_next_path(next_path),
        ),
    )
    response = RedirectResponse(
        token_client.authorization_url(
            state=state,
            nonce=nonce,
            code_challenge=pkce.challenge,
            prompt=prompt,
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/callback", include_in_schema=False)
async def callback(
    code: str | None = Query(default=None, max_length=4096),
    state: str | None = Query(default=None, max_length=256),
    error: str | None = Query(default=None, max_length=128),
    sessions: SessionManager = Depends(get_session_manager),
    token_client: OIDCTokenClient = Depends(get_token_client),
    validator: TokenValidator = Depends(get_token_validator),
) -> RedirectResponse:
    """Redeem the code, validate the identity token and create a session."""
    if error is not None:
        logger.info("Authorization request refused", extra={"reason": error})
        return _error_redirect("access_denied")
    if not code or not state:
        return _error_redirect("invalid_request")

    login_state = await sessions.pop_login_state(state)
    if login_state is None:
        logger.info("Unknown or replayed login state")
        return _error_redirect("state_expired")

    try:
        tokens = await token_client.exchange_code(
            code=code,
            code_verifier=login_state.code_verifier,
        )
    except OAuthExchangeError as exc:
        logger.warning("Code exchange failed", extra={"reason": exc.error})
        return _error_redirect("exchange_failed")

    if tokens.id_token is not None:
        try:
            await validator.validate_id_token(tokens.id_token, expected_nonce=login_state.nonce)
        except TokenValidationError as exc:
            logger.warning("ID token rejected", extra={"reason": exc.code})
            return _error_redirect("id_token_invalid")

    try:
        record = await sessions.create(tokens)
    except TokenValidationError as exc:
        logger.warning("Access token rejected at login", extra={"reason": exc.code})
        return _error_redirect("access_token_invalid")

    settings = get_settings()
    response = RedirectResponse(
        safe_next_path(login_state.next_path),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.set_cookie(
        settings.session_cookie_name,
        record.session_id,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(settings.logout_marker_cookie_name, path="/")
    response.headers["Cache-Control"] = "no-store"
    logger.info("Operator signed in", extra={"subject": record.principal.subject})
    return response


@router.get("/error", include_in_schema=False)
async def login_error(
    request: Request, reason: str | None = Query(default=None, max_length=64)
) -> HTMLResponse:
    """Public, human-readable sign-in failure page."""
    detail = _ERROR_DETAILS.get(reason or "", "Sign-in failed. Start again from the dashboard.")
    return render_error(request, title="Sign-in failed", detail=detail, status_code=400)


@router.post("/logout", include_in_schema=False)
async def logout(
    context: AuthContext = Depends(require_csrf),
    sessions: SessionManager = Depends(get_session_manager),
) -> RedirectResponse:
    """Delete the session, then hand the browser a one-time logout landing page.

    The POST redirects to a same-origin GET instead of straight to Keycloak, so
    the dashboard document (and its 3s polling) is unloaded before the browser
    leaves for the IdP. That removes the race where an in-flight poll's 401
    redirect interrupted the RP-initiated logout.
    """
    settings = get_settings()
    id_token = context.session.id_token if context.session is not None else None
    revoked = 0
    if context.session is not None:
        await sessions.delete(context.session.session_id)
        # A replaced cookie leaves earlier sessions of the same operator live
        # for the whole TTL; "Sign out" is expected to end all of them.
        revoked = await sessions.delete_all_for_subject(context.principal.subject)

    target = _end_session_url(id_token)
    token = await sessions.store_logout_target(target)
    response = RedirectResponse(
        f"/auth/logged-out?t={urllib.parse.quote(token)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.set_cookie(
        settings.logout_marker_cookie_name,
        "1",
        max_age=settings.logout_marker_ttl_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    logger.info(
        "Operator signed out",
        extra={"subject": context.principal.subject, "revoked_sessions": revoked},
    )
    return response


@router.get("/logged-out", include_in_schema=False)
async def logged_out(
    request: Request,
    token: str | None = Query(default=None, alias="t", max_length=256),
    sessions: SessionManager = Depends(get_session_manager),
) -> HTMLResponse:
    """Public, single-use landing page that completes the IdP logout."""
    end_session_url = await sessions.pop_logout_target(token) if token else None
    return render(
        request,
        "logged_out.html",
        context={
            "principal": None,
            "csrf_token": None,
            "end_session_url": end_session_url,
        },
    )


@router.get("/me", summary="Current identity")
async def me(context: AuthContext = Depends(get_auth_context)) -> dict[str, Any]:
    """Return the authenticated principal (no tokens, no raw claims)."""
    principal = context.principal
    return {
        "subject": principal.subject,
        "tenant_id": principal.tenant_id,
        "username": principal.username,
        "email": principal.email,
        "roles": sorted(principal.roles),
        "method": context.method,
    }


def _error_redirect(reason: str) -> RedirectResponse:
    return RedirectResponse(
        f"/auth/error?reason={urllib.parse.quote(reason)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _end_session_url(id_token: str | None) -> str:
    settings = get_settings()
    redirected = urlsplit(settings.keycloak_redirect_uri)
    post_logout = f"{redirected.scheme}://{redirected.netloc}/"
    params: dict[str, str] = {
        "client_id": settings.keycloak_client_id,
        "post_logout_redirect_uri": post_logout,
    }
    if id_token:
        params["id_token_hint"] = id_token
    return f"{settings.keycloak_end_session_endpoint}?{urllib.parse.urlencode(params)}"
