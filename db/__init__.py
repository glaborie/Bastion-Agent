"""Persistence layer: async session management, audit ledger and approvals."""

from db.audit import (
    AuditChainError,
    ChainVerification,
    append_audit_event,
    verify_audit_chain,
)
from db.models import (
    GENESIS_HASH,
    ApprovalStatus,
    AuditEventType,
    AuditLog,
    Base,
    PendingApproval,
    compute_record_hash,
    fingerprint_request,
    hash_approval_token,
    hash_payload,
    sign_approval_token,
    verify_approval_token,
)
from db.session import (
    dispose_engine,
    get_db_session,
    get_engine,
    get_session_factory,
    init_models,
    ping,
    session_scope,
)

__all__ = [
    "GENESIS_HASH",
    "ApprovalStatus",
    "AuditChainError",
    "AuditEventType",
    "AuditLog",
    "Base",
    "ChainVerification",
    "PendingApproval",
    "append_audit_event",
    "compute_record_hash",
    "dispose_engine",
    "fingerprint_request",
    "get_db_session",
    "get_engine",
    "get_session_factory",
    "hash_approval_token",
    "hash_payload",
    "init_models",
    "ping",
    "session_scope",
    "sign_approval_token",
    "verify_approval_token",
    "verify_audit_chain",
]
