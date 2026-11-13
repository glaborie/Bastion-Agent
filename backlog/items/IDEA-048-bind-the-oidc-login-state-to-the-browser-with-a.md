### IDEA-048: Bind the OIDC login state to the browser with a cookie

- status: inbox
- priority: P1
- phase: v0.3
- area: gateway
- tags: oidc, session, csrf
- depends-on: -
- spec: ADR-001
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`GET /auth/login` (`gateway/routers/auth.py:65-75`) stores state, nonce and PKCE verifier in Redis
keyed by the state string alone and sets no cookie on the browser that will return. `GET
/auth/callback` (`:105`) pops that record and issues the session cookie to whoever presents it.
`SameSite=Lax` does not stop a top-level GET navigation.

A victim who opens an attacker's callback link ends up holding a session authenticated as the
attacker, inside the attacker's tenant: chat prompts are written to the attacker's vault session
and ledger, and the dashboard shows the attacker's approval queue. Self-approval is still blocked,
so this is identity and tenant substitution plus misattribution, not privilege escalation.

**Outcome**

A callback whose state does not match the cookie set at login is rejected and no session is
created.

**Acceptance**

- [ ] A test asserts `/auth/login` sets an HttpOnly state cookie
- [ ] A callback presenting a valid state without that cookie is refused and creates no session
- [ ] A callback with the matching cookie still succeeds
