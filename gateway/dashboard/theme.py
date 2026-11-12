"""Dashboard colour-scheme preference (ADR-007 decision 1).

The choice lives in one first-party cookie and is rendered into ``<html>`` by
the server, so the first paint is already correct and no script has to run
before the page becomes readable. The cookie carries a theme name and nothing
else: no principal, tenant or session identifier, and it is ``HttpOnly``
because only the gateway needs to read it.
"""

from __future__ import annotations

from fastapi import Request, Response

THEMES: tuple[str, ...] = ("system", "light", "dark")
DEFAULT_THEME = "system"
THEME_COOKIE = "bastion_theme"

#: One year. A display preference, not a credential, so it may outlive a session.
THEME_COOKIE_MAX_AGE = 365 * 24 * 60 * 60


def normalise_theme(value: object) -> str:
    """Return a theme the renderer can trust, or ``system`` for anything else."""
    if isinstance(value, str) and value in THEMES:
        return value
    return DEFAULT_THEME


def theme_from_request(request: Request) -> str:
    """Read the theme from the request cookie; a missing or forged value is ``system``."""
    return normalise_theme(request.cookies.get(THEME_COOKIE))


def apply_theme_cookie(response: Response, theme: object) -> None:
    """Persist the allow-listed theme name on the response."""
    response.set_cookie(
        THEME_COOKIE,
        normalise_theme(theme),
        max_age=THEME_COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        samesite="lax",
    )
