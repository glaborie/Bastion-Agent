### IDEA-032: Add a persisted theme control and fix dark-mode contrast on the dashboard

- status: done
- priority: P3
- phase: v0.3
- area: gateway
- tags: dashboard, accessibility, css, ux
- depends-on: -
- spec: ADR-007
- created: 2026-11-12
- updated: 2026-11-12
- source: session request on 2026-11-12 ("implement darkmode on the dashboard")

**Problem**

The dashboard already goes dark implicitly and cannot be told to. `gateway/dashboard/templates/base.html:6` sets `<meta name="color-scheme" content="light dark">` and Pico 2.0.6 resolves `prefers-color-scheme`, so the theme follows the operating system and an operator whose OS stays light has no way to choose dark for a night or on-call shift: no template carries a toggle, `gateway/dashboard/static/` holds no theme script, and nothing persists a choice. The dashboard's own colours are literals rather than tokens — `#1b7f4b` for `.badge-ok`/`.chat-status.ok` and `#a4161a` for `.badge-bad`, `.alert` and `.chat-status.error` (`gateway/dashboard/static/style.css:74-87,220-226`) — so they do not adapt, and the red status text is roughly 2.3:1 against Pico's dark surface, below the WCAG AA 4.5:1 threshold. `CONTROL.md:147` nonetheless lists "**Dark/Light Toggle**: Tailwind `dark:` variant + `localStorage` persistence" under shipped features while Tailwind appears nowhere in the tree, the same document-claims-a-control pattern IDEA-011 reconciled for rate limiting.

**Outcome**

Every dashboard page offers a three-state theme control — system, light, dark — that defaults to system so today's behaviour is unchanged, applies the stored choice in `<head>` before first paint so a dark reload does not flash light, and persists only the theme name as a first-party asset under the strict `script-src 'self'` CSP: no inline `<script>`, no CDN, no new asset host (ADR-007 decisions 1 and 5). Every colour the dashboard sets itself is either a Pico token or a scheme-aware value that meets AA in both schemes, and `CONTROL.md` plus ADR-007 decision 1 describe what actually ships.

**Acceptance**

- [x] `uv run pytest tests/test_dashboard_theme.py -q` asserts every dashboard page renders the control, loads exactly one first-party theme script from `/static/`, and contains no inline `<script>`; the CSP in `gateway/main.py:46` is unchanged
- [x] No flash on reload: with the stored preference set to dark the first paint is dark, proven by a rendered-page test asserting the theme is resolved in `<head>` — a server-rendered `data-theme` on `<html>`, or a first-party script loaded synchronously there — never by a deferred script or an htmx swap
- [x] A request with no stored preference keeps `system` and renders the markup shipped today, and the persisted value is one of `system|light|dark` carrying no principal, tenant or session identifier, so a shared browser exposes a display choice and nothing else; clearing it falls back to `system`
- [x] A test computes the WCAG contrast ratio of every literal colour in `gateway/dashboard/static/style.css` against the Pico surface it is drawn on in both schemes and fails below 4.5:1, with the shipped `#a4161a` and `#1b7f4b` replaced by tokens or scheme-aware values so it passes
- [x] `CONTROL.md:147` no longer claims a Tailwind `dark:` variant, `grep -rn "tailwind" CONTROL.md gateway/` returns nothing, and ADR-007 decision 1 records the three-state control, its storage and the first-paint rule; `uv run python scripts/check_adrs.py` passes
- [x] `uv run pytest -q`, `ruff check .`, `ruff format --check .`, `mypy` and `pylint` stay green, and `tests/test_dashboard.py` passes with the toggle added

**Notes**

- Deduplication: grepped `BACKLOG.md`, `docs/adr/`, `CONTROL.md`, `COMPLIANCE.md` and `HANDOVER_SPEC.md` for `dark`, `theme`, `stylesheet`, `css`, `prefers-color` and `contrast`. No backlog item covers theming; the only theme hits are ADR-007 decision 1 (which records the automatic media-query behaviour that already ships), `CONTROL.md:147`, `COMPLIANCE.md:40` and `HANDOVER_SPEC.md:92,182`. IDEA-011 (done) reconciled the rate-limit claim and left the theme line untouched; IDEA-012 (done) added the demo console; IDEA-002 (done) is the approvals transport. So this is not "already decided and built": automatic dark is built, the manual control and the contrast repair are not.
- Classification: `P3`/`v0.3`/`gateway`. Cosmetic capability with no security invariant at stake and nothing broken in the guardrails, so not `P0`/`P1`; `P3` because it carries no phase commitment and no ADR-008 phase line names dashboard theming. `v0.3` is the current phase and the conservative home for a fix with no obvious phase; triage may pull it into `v0.2` as polish on shipped UI, or reject the toggle and keep only the documentation correction.
- Two separable halves, as in IDEA-011: (a) the `CONTROL.md:147` and ADR-007 drift, provable without the control; (b) the control and the contrast repair. The acceptance is written so (a) can ship alone if triage declines (b).
- Open decisions the ADR must take rather than this item preselecting: a cookie versus `localStorage` for persistence — a cookie renders the attribute server-side with no script but adds a per-response value, `localStorage` needs a first-party synchronous script in `<head>` — and whether the control is a three-state select or a two-state toggle with `system` reached by clearing it.
- Honest limits: the contrast check covers the dashboard's own CSS, not Pico's defaults, the vendored htmx fragments or keyboard navigation; `CONTROL.md`'s P2 list (shortcuts, command palette) stays out of scope; and the automatic dark mode already shipping means the item is a manual override plus a colour repair, not a from-scratch dark theme.
- Intake only: no template, CSS, script, test, document or ADR edit is part of this capture.

**Implementation notes (2026-11-12)**

- Started at explicit request while `inbox`/v0.3 on branch `idea-032-dashboard-theme`; promoted straight to `active` because the operator asked for the toggle and its persistence in the same turn.
- Storage decision (was an open question): one first-party cookie `bastion_theme` (`HttpOnly`, `SameSite=Lax`, `Path=/`, one-year `Max-Age`) rather than `localStorage`. The server renders `data-theme` on `<html>`, so the first paint is correct without any script, the value is an allow-list entry (`system|light|dark` — anything else renders as `system`), and a shared browser stores a display choice and no identity. `POST /dashboard/theme` (`gateway/dashboard/routes.py`, operator/admin + CSRF + the login `next` guard) writes it; `gateway/dashboard/theme.py` owns the list and the cookie flags; `gateway/dashboard/templating.py` injects the resolved theme into every render, error pages included.
- Control shape: three submit buttons (Auto / Light / Dark) in the operator bar, so it works with JavaScript disabled (full reload, server persists). `gateway/dashboard/static/theme.js` is progressive enhancement only: it posts the same form with `Accept: application/json`, gets `204`, flips the attribute and `aria-pressed` in place, and falls back to `form.submit()` if the request fails. It never touches `document.cookie` (the cookie is `HttpOnly`) and the CSP still allows only `script-src 'self'` with no inline script or handler.
- Colour repair: `style.css` now has no literal colour. `--bastion-ok`/`--bastion-danger` resolve to Pico's `--pico-ins-color`/`--pico-del-color`, and badge text uses `var(--pico-background-color)` as the on-colour, so the same rule is white-on-dark-green in the light palette and dark-on-pale-green in the dark one. Measured ratios (recomputed by the test from the vendored palette): status text on page background 6.48 light / 6.94 dark for ok, 7.83 / 5.89 for danger; on the dark card 6.59 / 5.60; badge text 6.48 / 6.94 (ok) and 7.83 / 5.89 (danger). All ≥ 4.5:1.
- `tests/test_dashboard_theme.py` (21 tests): control on all four dashboard pages, one `/static/theme.js`, zero inline scripts, unchanged `script-src 'self'`; server-rendered `data-theme` for `light`/`dark`; no attribute and no `Set-Cookie` identity for `system`; forged cookie → `system`; cookie flags and allow-list on a POST; `204` for the fetch path; `303` with a safe `next`; `//`, `https://` and backslash targets redirected to `/dashboard`; CSRF required; `readonly` refused; `theme.js` first-party and free of `innerHTML`/`eval`/`localStorage`; media-query dark and forced dark palettes equal; WCAG AA on both surfaces in all three palettes; stylesheet literal-free and token-mapped.
- Documents: `CONTROL.md` §9 states the shipped three-state control instead of the Tailwind claim (`grep -rn tailwind CONTROL.md gateway/` is empty); ADR-007 decision 1 gains the colour-scheme paragraph (states, cookie, first-paint rule, progressive enhancement, token/contrast rule) and decision 5 names the control in `base.html`.
- Gates on this branch: `scripts/gate.sh --integration` → 10/10 (ruff lint/format, mypy 79 files, pylint 10.00/10, pytest 741 passed / 12 skipped, ADRs, tool catalog, RBAC, DREAD, backlog).
- Honest limits: no browser was available, so the toggle was verified through rendered HTML and the request/response contract, not a visual pass; the contrast test covers the dashboard's own CSS and the Pico surfaces it draws on, not Pico's own components, htmx fragments or focus rings; `system` follows the OS and cannot be previewed against the other palette without changing the OS setting.
