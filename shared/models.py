from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class UserRecord(BaseModel):
    id: str
    username: str
    email: EmailStr
    password_hash: str
    roles: list[str]
    tenant_id: str
    department: str
    clearance_level: int = Field(default=1, ge=1, le=5)
    mfa_enabled: bool = False
    mfa_secret: str | None = None
    disabled: bool = False


class OAuthClient(BaseModel):
    client_id: str
    client_secret_hash: str | None = None
    allowed_grants: list[str]
    redirect_uris: list[str] = []
    scopes: list[str] = []
    client_type: Literal["public", "confidential", "service"] = "public"


class AuthorizationCodeRecord(BaseModel):
    code_id: str
    user_id: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    expires_at: datetime
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    csrf_token: str
    tenant_id: str
    risk_level: str = "low"
    trusted_device: bool = False


class RefreshSession(BaseModel):
    session_id: str
    family_id: str
    user_id: str
    client_id: str
    token_hash: str
    csrf_token: str
    expires_at: datetime
    rotated_at: datetime | None = None
    replaced_by: str | None = None
    revoked_at: datetime | None = None
    device_fingerprint: str | None = None
    issued_ip: str | None = None
    tenant_id: str
    scopes: list[str]
    risk_level: str = "low"
    trusted_device: bool = False


class PendingMfaChallenge(BaseModel):
    challenge_id: str
    user_id: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    expires_at: datetime
    tenant_id: str
    device_fingerprint_hash: str | None = None
    ip_address: str | None = None
    risk_level: str = "medium"


class AuditEvent(BaseModel):
    event_type: str
    actor_id: str | None = None
    client_id: str | None = None
    ip_address: str | None = None
    status: Literal["success", "failure", "suspicious", "info"]
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class SubjectContext(BaseModel):
    subject_id: str
    roles: list[str]
    tenant_id: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    scopes: list[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    obligations: list[str] = Field(default_factory=list)
