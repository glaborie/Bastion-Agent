"""Dashboard colour-scheme control, persistence and contrast floor (ADR-007).

The theme is a display preference, never an identity: the tests below pin the
allow-list, the cookie flags, the server-side first paint and the CSP shape, and
then compute WCAG contrast for the palette the dashboard actually ships.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from db.models import utcnow
from db.session import get_db_session
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.auth.session import SessionRecord
from gateway.dashboard.theme import THEME_COOKIE
from gateway.main import create_app
from tests.conftest import requires_database

OPERATOR = Principal(
    subject="alice-sub", tenant_id="acme", username="alice", roles=frozenset({"operator"})
)
READONLY = Principal(
    subject="dave-sub", tenant_id="acme", username="dave", roles=frozenset({"readonly"})
)
CSRF_TOKEN = "csrf-token"

ROOT = Path(__file__).resolve().parents[1]
STYLE_CSS = ROOT / "gateway" / "dashboard" / "static" / "style.css"
THEME_JS = ROOT / "gateway" / "dashboard" / "static" / "theme.js"
PICO_CSS = ROOT / "gateway" / "dashboard" / "static" / "vendor" / "pico-2.0.6.min.css"

DASHBOARD_PAGES = ("/dashboard", "/dashboard/audit", "/dashboard/chat", "/dashboard/demo")


def session_context(principal: Principal) -> AuthContext:
    now = utcnow()
    record = SessionRecord(
        session_id="session-theme",
        principal=principal,
        access_token="access-token",
        csrf_token=CSRF_TOKEN,
        created_at=now,
        access_expires_at=now + timedelta(minutes=5),
        last_seen_at=now,
    )
    return AuthContext(principal=principal, method="session", session=record)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, AuthContext]]]:
    """Cookie-authenticated caller, so CSRF and the session path are exercised."""
    app = create_app()
    state: dict[str, AuthContext] = {"context": session_context(OPERATOR)}
    app.dependency_overrides[get_auth_context] = lambda: state["context"]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as http:
        yield http, state


@pytest_asyncio.fixture
async def db_client(
    db_engine: AsyncEngine,
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, AuthContext]]]:
    app = create_app()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise
            await session.commit()

    state: dict[str, AuthContext] = {"context": session_context(OPERATOR)}
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_auth_context] = lambda: state["context"]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as http:
        yield http, state


def html_tag(document: str) -> str:
    match = re.search(r"<html[^>]*>", document)
    assert match is not None, "the page has no <html> tag"
    return match.group(0)


def inline_scripts(document: str) -> list[str]:
    """Every <script> without a src attribute is inline and forbidden by the CSP."""
    return re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", document, flags=re.IGNORECASE)


@pytest.mark.integration
@requires_database
@pytest.mark.parametrize("path", DASHBOARD_PAGES)
async def test_every_dashboard_page_offers_the_theme_control(
    db_client: tuple[httpx.AsyncClient, dict[str, Any]], path: str
) -> None:
    http, _state = db_client
    response = await http.get(path)

    assert response.status_code == 200
    assert response.text.count("/static/theme.js") == 1
    assert inline_scripts(response.text) == []
    assert 'action="/dashboard/theme"' in response.text
    assert "data-theme-form" in response.text
    for theme in ("system", "light", "dark"):
        assert f'value="{theme}"' in response.text
    # Default is system: the attribute is absent so Pico's media query decides.
    assert "data-theme=" not in html_tag(response.text)

    script_directive = response.headers["content-security-policy"].split("script-src")[1]
    assert script_directive.startswith(" 'self';")
    assert "unsafe-inline" not in script_directive.split(";")[0]


@pytest.mark.integration
@requires_database
@pytest.mark.parametrize("theme", ["light", "dark"])
async def test_the_stored_theme_is_rendered_before_the_first_paint(
    db_client: tuple[httpx.AsyncClient, dict[str, Any]], theme: str
) -> None:
    http, _state = db_client
    http.cookies.set(THEME_COOKIE, theme)

    for path in ("/dashboard", "/dashboard/chat"):
        response = await http.get(path)
        assert response.status_code == 200
        assert f'data-theme="{theme}"' in html_tag(response.text)
        assert 'aria-pressed="true"' in response.text


@pytest.mark.integration
@requires_database
async def test_clearing_the_cookie_falls_back_to_system(
    db_client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, _state = db_client
    http.cookies.set(THEME_COOKIE, "dark")
    assert 'data-theme="dark"' in html_tag((await http.get("/dashboard/chat")).text)

    http.cookies.clear()
    assert "data-theme=" not in html_tag((await http.get("/dashboard/chat")).text)


async def test_a_forged_cookie_value_cannot_select_a_theme(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, _state = client
    http.cookies.set(THEME_COOKIE, "purple")

    response = await http.get("/dashboard/chat")

    assert response.status_code == 200
    assert "data-theme=" not in html_tag(response.text)


async def test_theme_choice_is_persisted_in_one_first_party_cookie(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, _state = client

    response = await http.post(
        "/dashboard/theme",
        data={
            "theme": "dark",
            "next": "/dashboard/audit?event_type=INPUT_RECEIVED",
            "csrf_token": CSRF_TOKEN,
        },
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/audit?event_type=INPUT_RECEIVED"
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{THEME_COOKIE}=dark")
    for flag in ("HttpOnly", "Path=/", "SameSite=lax", "Max-Age=31536000"):
        assert flag.lower() in cookie.lower()
    # A display choice, never an identity: no subject, tenant or session leaks in.
    for forbidden in ("alice", "acme", "session-theme", "access-token"):
        assert forbidden not in cookie


async def test_the_script_switches_without_a_reload(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, _state = client

    response = await http.post(
        "/dashboard/theme",
        data={"theme": "light", "next": "/dashboard", "csrf_token": CSRF_TOKEN},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 204
    assert response.headers["set-cookie"].startswith(f"{THEME_COOKIE}=light")


async def test_an_unknown_theme_persists_system(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, _state = client

    response = await http.post(
        "/dashboard/theme",
        data={"theme": "solarized", "csrf_token": CSRF_TOKEN},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert response.headers["set-cookie"].startswith(f"{THEME_COOKIE}=system")


@pytest.mark.parametrize("target", ["//evil.example", "https://evil.example", "/\\evil"])
async def test_the_return_target_cannot_leave_the_dashboard(
    client: tuple[httpx.AsyncClient, dict[str, Any]], target: str
) -> None:
    http, _state = client

    response = await http.post(
        "/dashboard/theme",
        data={"theme": "dark", "next": target, "csrf_token": CSRF_TOKEN},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


async def test_the_theme_form_requires_csrf(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, _state = client

    assert (await http.post("/dashboard/theme", data={"theme": "dark"})).status_code == 403

    response = await http.post(
        "/dashboard/theme",
        data={"theme": "dark"},
        headers={"X-CSRF-Token": CSRF_TOKEN, "Accept": "application/json"},
    )
    assert response.status_code == 204


async def test_a_stale_htmx_form_is_told_to_reload(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """A document older than a re-login: 403, and htmx reloads the page."""
    http, _state = client

    # htmx would otherwise swap the 403 error page into the target element and
    # leave every later click on the same stale form failing.
    response = await http.post(
        "/dashboard/theme",
        data={"theme": "dark", "csrf_token": "token-from-a-replaced-session"},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 403
    assert response.headers["HX-Redirect"] == "/dashboard"


async def test_a_principal_without_dashboard_access_cannot_set_a_theme(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, state = client
    state["context"] = session_context(READONLY)

    response = await http.post("/dashboard/theme", data={"theme": "dark", "csrf_token": CSRF_TOKEN})

    assert response.status_code == 403
    assert "set-cookie" not in response.headers


async def test_the_theme_script_is_first_party_and_touches_no_html(
    client: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    http, _state = client

    response = await http.get("/static/theme.js")

    assert response.status_code == 200
    assert "text/javascript" in response.headers["content-type"]
    assert "innerHTML" not in response.text
    assert "eval(" not in response.text
    assert "localStorage" not in response.text


def _block(css: str, selector: str) -> str:
    match = re.search(re.escape(selector) + r"\{([^{}]*)\}", css)
    assert match is not None, f"selector not found in the vendored Pico: {selector}"
    return match.group(1)


def _variables(block: str) -> dict[str, str]:
    return dict(re.findall(r"(--pico-[a-z0-9-]+):([^;]+)", block))


def _resolve(variables: dict[str, str], name: str) -> str:
    value = variables[name]
    for _ in range(4):
        if not value.startswith("var("):
            return value
        value = variables[value.removeprefix("var(").removesuffix(")")]
    raise AssertionError(f"unresolved custom property chain at {name}")


def _channel(component: int) -> float:
    channel = component / 255
    return channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4


def _luminance(colour: str) -> float:
    match = re.fullmatch(r"#([0-9a-fA-F]{3,6})", colour)
    assert match is not None, f"expected a #rgb or #rrggbb literal, got {colour!r}"
    digits = match.group(1)
    if len(digits) == 3:
        digits = "".join(component * 2 for component in digits)
    assert len(digits) == 6, f"expected a #rgb or #rrggbb literal, got {colour!r}"
    red, green, blue = (int(digits[index : index + 2], 16) for index in (0, 2, 4))
    return 0.2126 * _channel(red) + 0.7152 * _channel(green) + 0.0722 * _channel(blue)


def _contrast(foreground: str, background: str) -> float:
    light, dark = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def _palettes() -> dict[str, dict[str, str]]:
    pico = PICO_CSS.read_text(encoding="utf-8")
    blocks = {
        "light": _variables(_block(pico, "[data-theme=light]")),
        "dark": _variables(_block(pico, "[data-theme=dark]")),
        "system-dark": _variables(_block(pico, ":root:not([data-theme])")),
    }
    palettes: dict[str, dict[str, str]] = {}
    for name, variables in blocks.items():
        palettes[name] = {
            "ins": _resolve(variables, "--pico-ins-color"),
            "del": _resolve(variables, "--pico-del-color"),
            "background": _resolve(variables, "--pico-background-color"),
            "card": _resolve(variables, "--pico-card-background-color"),
        }
    return palettes


def test_the_system_and_forced_dark_palettes_agree() -> None:
    """``system`` on a dark OS must look exactly like an explicit ``dark``."""
    palettes = _palettes()

    assert palettes["system-dark"] == palettes["dark"]


def test_every_status_colour_meets_wcag_aa_in_both_schemes() -> None:
    palettes = _palettes()

    for name, palette in palettes.items():
        for surface in ("background", "card"):
            for accent in ("ins", "del"):
                # Status text drawn on the page and on a card.
                assert _contrast(palette[accent], palette[surface]) >= 4.5, (
                    name,
                    accent,
                    surface,
                )
                # A badge uses the accent as a background with page-coloured text.
                assert _contrast(palette[surface], palette[accent]) >= 4.5, (
                    name,
                    surface,
                    accent,
                )


def test_the_dashboard_stylesheet_has_no_literal_colour() -> None:
    """Every colour must come from a token the contrast test can resolve."""
    style = STYLE_CSS.read_text(encoding="utf-8")

    assert re.findall(r"#[0-9a-fA-F]{3,8}\b", style) == []
    assert "--bastion-ok: var(--pico-ins-color)" in style
    assert "--bastion-danger: var(--pico-del-color)" in style
    assert "--bastion-on-ok: var(--pico-background-color)" in style
    assert "--bastion-on-danger: var(--pico-background-color)" in style
    assert ".badge-ok {\n  background: var(--bastion-ok);" in style
    assert ".chat-status.error {\n  color: var(--bastion-danger);" in style


def base_html_theme_form() -> str:
    template = ROOT / "gateway" / "dashboard" / "templates" / "base.html"
    return template.read_text(encoding="utf-8")


def test_the_theme_script_never_reads_or_writes_the_cookie() -> None:
    """The cookie is HttpOnly; only the POST may change it."""
    script = THEME_JS.read_text(encoding="utf-8")

    assert "document.cookie" not in script
    assert "/dashboard/theme" in base_html_theme_form()
