"""East-west TLS configuration (ADR-019).

The unit half proves the client contexts fail closed and carry the internal CA.
The live half runs only when ``PKI_TEST_*`` points at a server started from
``docker-compose.pki.yml``; it asserts refusal, never a successful plaintext or
password-only connection.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import pytest

from db.redis import arq_redis_settings, redis_tls_kwargs
from db.session import database_ssl_context
from settings import Settings

PKI_TEST_DATABASE_URL = os.getenv("PKI_TEST_DATABASE_URL", "")
PKI_TEST_REDIS_URL = os.getenv("PKI_TEST_REDIS_URL", "")
PKI_TEST_CA = os.getenv("PKI_TEST_CA", "")
PKI_TEST_CERT = os.getenv("PKI_TEST_CERT", "")
PKI_TEST_KEY = os.getenv("PKI_TEST_KEY", "")

requires_pki = pytest.mark.skipif(
    not (PKI_TEST_DATABASE_URL and PKI_TEST_CA and PKI_TEST_CERT and PKI_TEST_KEY),
    reason="the pki profile is not running (set PKI_TEST_DATABASE_URL/CA/CERT/KEY)",
)


def make_settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _write_pki(tmp_path: Path, *, ca: bool = True, cert: bool = True) -> dict[str, str]:
    """Write a real CA bundle and client identity; the SSL context parses them."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    def name(common_name: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name("bastion-test-ca"))
        .issuer_name(name("bastion-test-ca"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(name("bastion"))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    paths = {
        "pki_ca_cert_path": str(tmp_path / "ca.crt"),
        "pki_client_cert_path": str(tmp_path / "tls.crt"),
        "pki_client_key_path": str(tmp_path / "tls.key"),
    }
    if ca:
        Path(paths["pki_ca_cert_path"]).write_bytes(
            ca_cert.public_bytes(serialization.Encoding.PEM)
        )
    if cert:
        Path(paths["pki_client_cert_path"]).write_bytes(
            leaf_cert.public_bytes(serialization.Encoding.PEM)
        )
        Path(paths["pki_client_key_path"]).write_bytes(
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return paths


def test_disable_is_the_local_default() -> None:
    settings = make_settings()
    assert settings.database_ssl_mode == "disable"
    assert settings.redis_tls_enabled is False
    assert database_ssl_context(settings) is None
    assert not redis_tls_kwargs(settings)


def test_a_missing_ca_bundle_refuses_to_start(tmp_path: Path) -> None:
    paths = _write_pki(tmp_path, ca=False)
    settings = make_settings(database_ssl_mode="verify-full", **paths)
    with pytest.raises(RuntimeError, match="CA bundle"):
        database_ssl_context(settings)


def test_a_missing_client_certificate_refuses_to_start(tmp_path: Path) -> None:
    paths = _write_pki(tmp_path, cert=False)
    settings = make_settings(database_ssl_mode="verify-full", **paths)
    with pytest.raises(RuntimeError, match="client certificate"):
        database_ssl_context(settings)


def test_verify_full_trusts_only_the_internal_ca(tmp_path: Path) -> None:
    paths = _write_pki(tmp_path)
    context = database_ssl_context(make_settings(database_ssl_mode="verify-full", **paths))
    assert context is not None
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.get_ca_certs(), "the internal CA must be the only trust anchor"


def test_require_encrypts_without_identity(tmp_path: Path) -> None:
    paths = _write_pki(tmp_path)
    context = database_ssl_context(make_settings(database_ssl_mode="require", **paths))
    assert context is not None
    assert context.verify_mode is ssl.CERT_NONE
    assert context.check_hostname is False


def test_redis_tls_requires_every_file(tmp_path: Path) -> None:
    paths = _write_pki(tmp_path, cert=False)
    settings = make_settings(redis_tls_enabled=True, **paths)
    with pytest.raises(RuntimeError, match="certificate"):
        redis_tls_kwargs(settings)


def test_a_rediss_dsn_implies_tls_even_when_the_flag_is_off(tmp_path: Path) -> None:
    paths = _write_pki(tmp_path)
    settings = make_settings(
        redis_tls_enabled=False,
        redis_url="rediss://:pw@redis:6379/0",
        **paths,
    )
    kwargs = redis_tls_kwargs(settings)
    assert kwargs["ssl_cert_reqs"] == "required"
    assert arq_redis_settings(settings).ssl is True


def test_arq_settings_carry_the_client_identity(tmp_path: Path) -> None:
    paths = _write_pki(tmp_path)
    settings = make_settings(redis_tls_enabled=True, **paths)
    arq = arq_redis_settings(settings)
    assert arq.ssl is True
    assert arq.ssl_cert_reqs == "required"
    assert arq.ssl_ca_certs == paths["pki_ca_cert_path"]
    assert arq.ssl_certfile == paths["pki_client_cert_path"]
    assert arq.ssl_keyfile == paths["pki_client_key_path"]


def test_the_oidc_client_trusts_the_configured_bundle(tmp_path: Path) -> None:
    from gateway.auth.oidc import _tls_verify

    bundle = tmp_path / "ca.crt"
    bundle.write_text("ca", encoding="utf-8")
    assert _tls_verify.__module__ == "gateway.auth.oidc"
    # The helper reads settings, so point the cache at a settings object.
    from settings import reset_settings_cache

    os.environ["OIDC_CA_CERT_PATH"] = str(bundle)
    reset_settings_cache()
    try:
        assert _tls_verify() == str(bundle)
        os.environ["OIDC_CA_CERT_PATH"] = str(tmp_path / "missing.crt")
        reset_settings_cache()
        with pytest.raises(RuntimeError, match="OIDC_CA_CERT_PATH"):
            _tls_verify()
    finally:
        os.environ.pop("OIDC_CA_CERT_PATH", None)
        reset_settings_cache()


# ---------------------------------------------------------------------------
# Live: only against a server started from docker-compose.pki.yml
# ---------------------------------------------------------------------------


@requires_pki
async def test_a_password_alone_cannot_reach_postgres() -> None:
    from asyncpg.exceptions import InvalidAuthorizationSpecificationError
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.ext.asyncio import create_async_engine

    # TLS without a client certificate: the server must refuse, not fall back.
    engine = create_async_engine(
        PKI_TEST_DATABASE_URL,
        connect_args={"ssl": ssl.create_default_context(cafile=PKI_TEST_CA)},
    )
    with pytest.raises((SQLAlchemyError, InvalidAuthorizationSpecificationError)) as caught:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    await engine.dispose()
    assert "client certificate" in str(caught.value).lower()


@requires_pki
async def test_the_client_certificate_is_accepted() -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    context = ssl.create_default_context(cafile=PKI_TEST_CA)
    context.load_cert_chain(certfile=PKI_TEST_CERT, keyfile=PKI_TEST_KEY)
    engine = create_async_engine(PKI_TEST_DATABASE_URL, connect_args={"ssl": context})
    async with engine.connect() as connection:
        assert (await connection.execute(text("SELECT 1"))).scalar() == 1
    await engine.dispose()


@requires_pki
@pytest.mark.skipif(not PKI_TEST_REDIS_URL, reason="PKI_TEST_REDIS_URL is not set")
async def test_a_certificate_less_client_cannot_write_to_redis() -> None:
    from redis.asyncio import Redis

    client = Redis.from_url(
        PKI_TEST_REDIS_URL,
        decode_responses=True,
        ssl_ca_certs=PKI_TEST_CA,
        socket_connect_timeout=5,
    )
    from redis.exceptions import ConnectionError as RedisConnectionError

    with pytest.raises((RedisConnectionError, OSError)):
        await client.set("pki:probe", "1")
    await client.aclose()
