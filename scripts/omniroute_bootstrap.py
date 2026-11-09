#!/usr/bin/env python3
"""Idempotently reconcile the OmniRoute routing contract for Bastion-Agent.

Creates/updates the llama.cpp provider node, the provider connections, the
`local-llama` / `cloud-primary` combos and the gateway API key, then smoke-tests
both aliases.

    uv run python scripts/omniroute_bootstrap.py --write-env

The API key is printed only when it is created (OmniRoute never reveals it
again); `--write-env` stores it in `.env` automatically.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8001"
ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

NODE_ID = "openai-compatible-chat-local"
NODE = {
    "name": "llama-cpp-local",
    "prefix": "llama",
    "apiType": "chat",
    "baseUrl": "http://llama-cpp:8080/v1",
    "type": "openai-compatible",
}
COMBOS = {
    "local-llama": {
        "strategy": "priority",
        "models": ["llama/qwen2.5-7b-instruct-q4_k_m"],
    },
    "cloud-primary": {
        "strategy": "priority",
        "models": [
            "openrouter/openai/gpt-4o-mini",
            "openrouter/anthropic/claude-haiku-4.5",
        ],
    },
}


def load_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def write_env_value(key: str, value: str) -> None:
    lines = ENV_FILE.read_text().splitlines()
    pattern = re.compile(rf"^{re.escape(key)}=")
    out = [f"{key}={value}" if pattern.match(line) else line for line in lines]
    if not any(pattern.match(line) for line in lines):
        out.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(out) + "\n")


class Admin:
    def __init__(self, password: str) -> None:
        self.password = password
        self.cookie: str | None = None

    def call(
        self, method: str, path: str, body: object | None = None, bearer: str | None = None
    ) -> tuple[int, str]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        request = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def login(self) -> None:
        _, _ = self.call("POST", "/api/auth/login", {"password": self.password})
        request = urllib.request.Request(
            BASE_URL + "/api/auth/login",
            data=json.dumps({"password": self.password}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            cookie = response.headers.get("Set-Cookie", "")
        self.cookie = cookie.split(";")[0] if cookie else None
        if not self.cookie:
            raise SystemExit("OmniRoute login failed: no session cookie returned")


def ensure_node(admin: Admin, llama_key: str) -> None:
    status, body = admin.call("GET", "/api/provider-nodes")
    nodes = json.loads(body).get("nodes", []) if status == 200 else []
    if any(node["id"] == NODE_ID for node in nodes):
        status, body = admin.call("PUT", f"/api/provider-nodes/{NODE_ID}", NODE)
        print(f"provider node updated: {status}")
    else:
        status, body = admin.call(
            "POST", "/api/provider-nodes", {**NODE, "providerIdSuffix": "local"}
        )
        print(f"provider node created: {status}")
    if status >= 300:
        raise SystemExit(f"provider node failed: {body[:400]}")


def ensure_connection(
    admin: Admin, provider: str, name: str, url: str, api_key: str, *, llama_conn: bool = False
) -> str:
    status, body = admin.call("GET", "/api/providers")
    connections = json.loads(body).get("connections", []) if status == 200 else []
    existing = next(
        (c for c in connections if c["provider"] == provider and c["name"] == name), None
    )
    if existing is None and llama_conn:
        existing = next((c for c in connections if c["provider"] == provider), None)
    if existing is None:
        status, body = admin.call(
            "POST",
            "/api/providers",
            {"provider": provider, "name": name, "url": url, "apiKey": api_key},
        )
        print(f"connection created ({provider}): {status}")
        if status >= 300:
            raise SystemExit(f"connection failed: {body[:400]}")
        connection_id = json.loads(body)["connection"]["id"]
    else:
        connection_id = existing["id"]
        print(f"connection exists ({provider}): {connection_id[:8]}")
    status, _ = admin.call("PATCH", f"/api/providers/{connection_id}", {"isActive": True})
    if status >= 300:
        raise SystemExit(f"could not activate {provider}: {status}")
    status, body = admin.call("POST", f"/api/providers/{connection_id}/test")
    print(f"connection test ({provider}): {status} {body[:120]}")
    return connection_id


def ensure_combos(admin: Admin) -> None:
    status, body = admin.call("GET", "/api/combos")
    existing = {c["name"]: c for c in json.loads(body).get("combos", [])} if status == 200 else {}
    for name, spec in COMBOS.items():
        payload = {"name": name, **spec}
        if name in existing:
            combo_id = existing[name]["id"]
            status, body = admin.call("PUT", f"/api/combos/{combo_id}", payload)
            print(f"combo updated ({name}): {status}")
        else:
            status, body = admin.call("POST", "/api/combos", payload)
            print(f"combo created ({name}): {status}")
        if status >= 300:
            raise SystemExit(f"combo {name} failed: {body[:400]}")


def key_is_functional(key: str) -> bool:
    """OmniRoute never reveals keys again, so prove the configured one works."""
    if not key:
        return False
    request = urllib.request.Request(
        BASE_URL + "/v1/models", headers={"Authorization": "Bearer " + key}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status == 200
    except urllib.error.HTTPError:
        return False


def ensure_key(admin: Admin, env: dict[str, str]) -> str:
    configured = env.get("OMNIROUTE_API_KEY", "")
    # OmniRoute exposes no key preview, so reconcile by count + functional check.
    status, body = admin.call("GET", "/api/keys")
    managed = [
        key for key in json.loads(body).get("keys", []) if key.get("name") == "bastion-gateway"
    ] if status == 200 else []
    if configured and len(managed) == 1 and key_is_functional(configured):
        print("gateway key: registered and functional")
        return configured
    # Retire every key this bootstrap previously created so exactly one remains.
    for key in managed:
        admin.call("DELETE", f"/api/keys/{key['id']}")
    status, body = admin.call("POST", "/api/keys", {"name": "bastion-gateway"})
    if status >= 300:
        raise SystemExit(f"key creation failed: {body[:400]}")
    created = json.loads(body)["key"]
    print(f"gateway key created: {created}")
    return created


def smoke_test(api_key: str) -> None:
    for alias in COMBOS:
        request = urllib.request.Request(
            BASE_URL + "/v1/chat/completions",
            data=json.dumps(
                {
                    "model": alias,
                    "messages": [{"role": "user", "content": "Reply with exactly: ALIAS OK"}],
                    "max_tokens": 16,
                    "temperature": 0,
                }
            ).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                payload = json.loads(response.read())
            content = payload["choices"][0]["message"]["content"].strip()
            print(f"smoke {alias}: OK ({payload['model']}) -> {content!r}")
        except urllib.error.HTTPError as exc:
            print(f"smoke {alias}: HTTP {exc.code} {exc.read()[:200]!r}")
            raise SystemExit(1) from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-env", action="store_true", help="store a newly created gateway key in .env"
    )
    parser.add_argument("--skip-smoke", action="store_true", help="do not call the aliases")
    args = parser.parse_args()

    env = load_env()
    admin = Admin(env.get("OMNIROUTE_ADMIN_PASSWORD", os.getenv("OMNIROUTE_ADMIN_PASSWORD", "")))
    admin.login()
    print("authenticated with OmniRoute")

    llama_key = env.get("LLAMA_API_KEY") or "dev-only-llama-api-key"
    openrouter_key = env.get("OPENROUTER_API_KEY", "")
    if not openrouter_key:
        raise SystemExit("OPENROUTER_API_KEY is not set in .env")

    ensure_node(admin, llama_key)
    ensure_connection(admin, NODE_ID, NODE["name"], NODE["baseUrl"], llama_key, llama_conn=True)
    ensure_connection(
        admin, "openrouter", "openrouter", "https://openrouter.ai/api/v1", openrouter_key
    )
    ensure_combos(admin)
    key = ensure_key(admin, env)
    if args.write_env and key != env.get("OMNIROUTE_API_KEY"):
        write_env_value("OMNIROUTE_API_KEY", key)
        print("wrote OMNIROUTE_API_KEY to .env (recreate gateway/worker to apply)")
    if not args.skip_smoke:
        smoke_test(key)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - operator-facing
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
