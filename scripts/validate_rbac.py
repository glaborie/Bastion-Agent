#!/usr/bin/env python3
"""Validate the declarative RBAC policy against Keycloak and the tool registry.

Three sources must agree, or an operator will discover the mismatch during an
incident:

* ``gateway/auth/roles.py`` — the roles the application understands;
* ``config/keycloak/realm-export.json`` — the roles and users the IdP seeds;
* ``@tool`` declarations — the role each tool requires.

It also proves that every mutating tool is actually approvable: at least two
seeded identities must satisfy its ``required_role``, otherwise four-eyes can
never complete.

    uv run python scripts/validate_rbac.py
    uv run python scripts/validate_rbac.py --strict --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agent.tools import ToolDefinition, list_tools
from gateway.auth.roles import ROLE_NAMES, is_satisfied
from settings import get_settings

DEFAULT_REALM = Path("config/keycloak/realm-export.json")
CLI_CLIENT_ID = "bastion-cli"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate RBAC policy consistency.")
    parser.add_argument(
        "--realm",
        type=Path,
        default=DEFAULT_REALM,
        help=f"Keycloak realm export (default: {DEFAULT_REALM})",
    )
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser.parse_args()


def load_realm(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"realm export not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a realm export object")
    return payload


def _check_roles(realm: dict[str, Any], errors: list[str]) -> set[str]:
    realm_roles = {
        role["name"] for role in realm.get("roles", {}).get("realm", []) if "name" in role
    }
    unknown = sorted(realm_roles - ROLE_NAMES)
    missing = sorted(ROLE_NAMES - realm_roles)
    if unknown:
        errors.append(f"realm defines role(s) the code does not know: {unknown}")
    if missing:
        errors.append(f"code role(s) missing from the realm: {missing}")
    return realm_roles


def _check_users(
    realm: dict[str, Any], errors: list[str], warnings: list[str]
) -> dict[str, frozenset[str]]:
    users: dict[str, frozenset[str]] = {}
    for user in realm.get("users", []):
        username = user.get("username")
        if not isinstance(username, str) or not username:
            errors.append("a seeded user has no username")
            continue
        granted = frozenset(user.get("realmRoles") or [])
        users[username] = granted
        if not granted:
            errors.append(f"user {username!r} has no bastion role")
        unknown = sorted(granted - ROLE_NAMES)
        if unknown:
            errors.append(f"user {username!r} has unknown role(s): {unknown}")
        if not user.get("enabled", True):
            warnings.append(f"user {username!r} is disabled; it cannot approve anything")
    return users


def _check_tools(
    tools: list[ToolDefinition], users: dict[str, frozenset[str]], errors: list[str]
) -> None:
    for definition in tools:
        role = definition.required_role
        if role is not None and role not in ROLE_NAMES:
            errors.append(f"tool {definition.name!r} requires unknown role {role!r}")
        if definition.read_only:
            continue
        if role is None:
            errors.append(f"mutating tool {definition.name!r} declares no required_role")
            continue
        approvers = [name for name, granted in users.items() if is_satisfied(granted, role)]
        if len(approvers) < 2:
            errors.append(
                f"tool {definition.name!r} requires {role!r}, but only "
                f"{len(approvers)} seeded user(s) satisfy it; four-eyes is impossible"
            )


def _check_clients(realm: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    settings = get_settings()
    clients = {client.get("clientId"): client for client in realm.get("clients", [])}

    gateway = clients.get(settings.keycloak_client_id)
    if gateway is None:
        errors.append(f"OIDC client {settings.keycloak_client_id!r} is missing from the realm")
    else:
        if gateway.get("publicClient"):
            errors.append(f"client {settings.keycloak_client_id!r} must be confidential")
        if not gateway.get("standardFlowEnabled", True):
            errors.append(f"client {settings.keycloak_client_id!r} must allow the code flow")
        redirects = set(gateway.get("redirectUris") or [])
        if settings.keycloak_redirect_uri not in redirects:
            errors.append(
                f"{settings.keycloak_redirect_uri!r} is not a registered redirect URI "
                f"for {settings.keycloak_client_id!r}"
            )

    cli = clients.get(CLI_CLIENT_ID)
    if cli is None:
        warnings.append(
            f"client {CLI_CLIENT_ID!r} is absent; the CLI/demo token flow is unavailable"
        )
        return
    if not cli.get("publicClient"):
        errors.append(f"client {CLI_CLIENT_ID!r} must be public")
    if not cli.get("directAccessGrantsEnabled"):
        errors.append(f"client {CLI_CLIENT_ID!r} must enable direct access grants")


def check(
    realm: dict[str, Any], tools: list[ToolDefinition]
) -> tuple[list[str], list[str], dict[str, Any]]:
    """Return ``(errors, warnings, summary)`` for the current policy."""
    errors: list[str] = []
    warnings: list[str] = []

    realm_roles = _check_roles(realm, errors)
    users = _check_users(realm, errors, warnings)
    _check_tools(tools, users, errors)
    _check_clients(realm, errors, warnings)

    for role in sorted(ROLE_NAMES):
        if not any(role in granted for granted in users.values()):
            warnings.append(f"no seeded user holds {role!r} directly")

    summary = {
        "realm_roles": sorted(realm_roles),
        "users": len(users),
        "tools": len(tools),
        "mutating_tools": sum(1 for definition in tools if not definition.read_only),
        "errors": errors,
        "warnings": warnings,
    }
    return errors, warnings, summary


def main() -> int:
    args = parse_args()
    try:
        realm = load_realm(args.realm)
    except (OSError, ValueError) as exc:
        print(f"realm error: {exc}", file=sys.stderr)
        return 1

    errors, warnings, summary = check(realm, list(list_tools()))
    failed = bool(errors) or (args.strict and bool(warnings))

    if args.json:
        print(json.dumps({"ok": not failed, **summary}, indent=2))
    else:
        print(
            f"realm roles : {', '.join(summary['realm_roles']) or '(none)'}\n"
            f"users       : {summary['users']}\n"
            f"tools       : {summary['tools']} "
            f"({summary['mutating_tools']} mutating)"
        )
        for warning in warnings:
            print(f"WARN: {warning}")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if not failed:
            print("OK: RBAC policy is consistent.")
        else:
            print(f"FAILED: {len(errors)} error(s), {len(warnings)} warning(s).", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
