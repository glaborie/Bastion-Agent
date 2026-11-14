#!/usr/bin/env python3
"""One-shot, idempotent Vault bootstrap for the dev stack.

Run inside the vault container once Vault is reachable:

1. Initialise Vault (Raft integrated storage) and persist the unseal key.
2. Unseal, so the container comes up ready to serve.
3. Create the fixed local dev root token.
4. Enable the KV v2 secrets engine at "bastion" and write the ACL policies.
5. Seed dev secrets (randomised, never committed) on first run only.

Production: replace the dev token with AppRole/K8s auth and inject unseal keys
via a secrets manager or HSM. This script is dev-only.
"""

import json
import os
import shutil
import subprocess
import sys
import time

VAULT_ADDR = os.environ.get("VAULT_ADDR", "https://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "dev-root-token-bastion")
POLICY_DIR = "/etc/vault.d/policies"
SECRETS_MOUNT = "bastion"
DEV_TOKEN = "dev-root-token-bastion"
VAULT_BIN = shutil.which("vault") or "vault"
# Dev only: the unseal key sits next to the raft data so a restart can unseal.
# Production uses a quorum of HSM-backed keys and never stores them on disk.
KEY_FILE = "/vault/data/unseal.key"


def write_key(key: str) -> None:
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key)


def read_key() -> str:
    try:
        with open(KEY_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except FileNotFoundError:
        return ""


def vault(*args, token=None, env_extra=None):
    env = dict(os.environ)
    env["VAULT_ADDR"] = VAULT_ADDR
    env["VAULT_TOKEN"] = token or VAULT_TOKEN
    env["VAULT_SKIP_VERIFY"] = "true"  # self-signed cert in dev
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [VAULT_BIN, *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 2):  # 2 is expected for some read ops
        print(f"  vault {' '.join(args)} -> rc={proc.returncode}")
        if proc.stderr.strip():
            print(f"    stderr: {proc.stderr.strip()[:300]}")
    return proc


def wait_ready(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = vault("status", "-format=json")
        if r.returncode == 0:
            try:
                data = json.loads(r.stdout)
                if data.get("initialized") and not data.get("sealed"):
                    return True
            except (ValueError, TypeError):
                pass
        time.sleep(2)
    return False


def main():
    print("[bootstrap] waiting for Vault to be initialised ...")
    vault("status")
    r = vault("status", "-format=json")
    # rc=2 means sealed but reachable, and still prints the JSON status.
    state = json.loads(r.stdout) if r.stdout.strip() else {}

    root_token = ""
    if not state.get("initialized"):
        print("[bootstrap] initialising (1 key, Raft integrated storage) ...")
        r = vault(
            "operator",
            "init",
            "-format=json",
            "-key-shares=1",
            "-key-threshold=1",
        )
        init = json.loads(r.stdout)
        write_key(init["unseal_keys_b64"][0])
        root_token = init["root_token"]
        # Re-read state after init.
        r = vault("status", "-format=json")
        state = json.loads(r.stdout)

    if state.get("sealed"):
        print("[bootstrap] unsealing ...")
        key = read_key()
        if not key:
            print(
                f"[bootstrap] ERROR: sealed and {KEY_FILE} is missing; "
                "remove the vault-data volume to re-initialise",
                file=sys.stderr,
            )
            sys.exit(1)
        vault("operator", "unseal", key)

    if not wait_ready():
        print("[bootstrap] ERROR: Vault did not become ready", file=sys.stderr)
        sys.exit(1)

    # The token the stack and the Makefile use; init only hands out a random one.
    if root_token:
        vault(
            "token",
            "create",
            f"-id={DEV_TOKEN}",
            "-policy=root",
            "-orphan",
            token=root_token,
        )

    print("[bootstrap] Vault is ready. Configuring secrets engine ...")

    # Enable KV v2 at the "bastion" mount point (the policies read bastion/data/*).
    vault("secrets", "enable", f"-path={SECRETS_MOUNT}", "-version=2", "kv")
    # Idempotent: ignore "path already in use" (exit code 1).

    # Write ACL policies.
    for name in sorted(os.listdir(POLICY_DIR)):
        if not name.endswith(".hcl"):
            continue
        path = os.path.join(POLICY_DIR, name)
        policy_name = name[:-4]  # strip .hcl
        print(f"[bootstrap] writing policy: {policy_name}")
        vault("policy", "write", policy_name, path)

    # Seed dev secrets (randomised; never committed to git) on first run only:
    # re-seeding would silently rotate creds the running stack already uses.
    if vault("kv", "get", f"{SECRETS_MOUNT}/db/postgres").returncode != 0:
        print("[bootstrap] seeding dev secrets ...")
        seed_secrets()
    else:
        print("[bootstrap] dev secrets already present; not re-seeding")

    print("[bootstrap] complete. Dev token: dev-root-token-bastion")
    print("[bootstrap] WARNING: rotate all tokens before any non-dev use.")


def seed_secrets() -> None:
    secrets = {
        "db/postgres": {
            "POSTGRES_USER": "bastion",
            "POSTGRES_PASSWORD": os.urandom(24).hex(),
            "POSTGRES_DB": "bastion",
        },
        "db/redis": {
            "REDIS_PASSWORD": os.urandom(24).hex(),
        },
        "db/keycloak": {
            "KEYCLOAK_ADMIN": "admin",
            "KEYCLOAK_ADMIN_PASSWORD": os.urandom(24).hex(),
            "KEYCLOAK_CLIENT_SECRET": os.urandom(32).hex(),
        },
        "db/minio": {
            "MINIO_ROOT_USER": "bastion-minio-root",
            "MINIO_ROOT_PASSWORD": os.urandom(24).hex(),
            "AUDIT_WITNESS_ACCESS_KEY": "bastion-witness",
            "AUDIT_WITNESS_SECRET_KEY": os.urandom(32).hex(),
        },
        "app/jwt": {
            "JOB_SIGNING_SECRET": os.urandom(32).hex(),
            "APPROVAL_HMAC_SECRET": os.urandom(32).hex(),
        },
        "app/oauth": {
            "OPENROUTER_API_KEY": "sk-local-dev",
            "OMNIROUTE_API_KEY": "sk-local-dev",
            "LLAMA_API_KEY": "dev-only-llama-api-key",
        },
    }
    for path, data in secrets.items():
        pairs = [f"{k}={v}" for k, v in data.items()]
        vault("kv", "put", f"{SECRETS_MOUNT}/{path}", *pairs)


if __name__ == "__main__":
    main()
