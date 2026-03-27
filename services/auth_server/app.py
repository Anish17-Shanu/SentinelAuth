import logging
from datetime import timedelta
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from shared.config import get_settings
from shared.dependencies import key_manager, require_csrf
from shared.middleware import SecurityHeadersMiddleware
from shared.models import AuditEvent, AuthorizationCodeRecord, PendingMfaChallenge, RefreshSession
from shared.security import fingerprint_hash, pkce_challenge, random_token, token_hash, utc_now, verify_secret, verify_totp
from shared.store import platform_store


settings = get_settings()
logger = logging.getLogger(__name__)
app = FastAPI(title="SentinelAuth Auth Server", version="1.1.0", docs_url="/docs" if settings.docs_enabled else None)
app.add_middleware(SecurityHeadersMiddleware)


class LoginRequest(BaseModel):
    username: str
    password: str = Field(min_length=12)
    client_id: str
    redirect_uri: str
    scope: str = "openid profile:read offline_access"
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    device_fingerprint: str | None = None
    mfa_code: str | None = None
    prompt: str | None = None


class MfaVerifyRequest(BaseModel):
    challenge_id: str
    mfa_code: str = Field(min_length=6, max_length=8)


class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str | None = None
    code: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None
    scope: str | None = None
    audience: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class RevokeRequest(BaseModel):
    token: str
    token_type_hint: str | None = None


async def write_audit(event_type: str, status_value: str, actor_id: str | None, client_id: str | None, ip_address: str | None, **details) -> None:
    await platform_store.record_audit_event(
        AuditEvent(
            event_type=event_type,
            actor_id=actor_id,
            client_id=client_id,
            ip_address=ip_address,
            status=status_value,
            details=details,
            created_at=utc_now(),
        )
    )


def build_token_response(access_token: str, refresh_token: str | None, csrf_token: str | None, expires_in: int, scope: str) -> dict:
    response = {
        "token_type": "Bearer",
        "access_token": access_token,
        "expires_in": expires_in,
        "scope": scope,
    }
    if refresh_token:
        response["refresh_token"] = refresh_token
    if csrf_token:
        response["csrf_token"] = csrf_token
    return response


async def assess_login_risk(user, request: Request, device_fingerprint: str | None) -> tuple[str, list[str], bool]:
    reasons: list[str] = []
    trusted_device = await platform_store.is_known_device(user.id, device_fingerprint)
    last_ip = await platform_store.get_last_seen_ip(user.id)
    request_ip = request.client.host if request.client else None

    score = 0
    if not device_fingerprint:
        score += 1
        reasons.append("missing_device_fingerprint")
    elif not trusted_device:
        score += 2
        reasons.append("new_device")
    if last_ip and request_ip and request_ip != last_ip:
        score += 1
        reasons.append("ip_shift")
    if user.clearance_level >= 4:
        score += 1
        reasons.append("privileged_account")

    if score >= 3:
        return "high", reasons, trusted_device
    if score >= 1:
        return "medium", reasons, trusted_device
    return "low", reasons, trusted_device


async def issue_authorization_code(
    *,
    user,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    code_challenge: str | None,
    code_challenge_method: str | None,
    risk_level: str,
    trusted_device: bool,
) -> dict:
    code = random_token(32)
    csrf_token = random_token(24)
    await platform_store.register_auth_code(
        code,
        AuthorizationCodeRecord(
            code_id=token_hash(code),
            user_id=user.id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            expires_at=utc_now().replace(microsecond=0) + timedelta(seconds=settings.authorization_code_ttl_seconds),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            csrf_token=csrf_token,
            tenant_id=user.tenant_id,
            risk_level=risk_level,
            trusted_device=trusted_device,
        ),
    )
    return {
        "authorization_code": code,
        "expires_in": settings.authorization_code_ttl_seconds,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "risk_level": risk_level,
        "trusted_device": trusted_device,
    }


def build_id_token(user, client_id: str, scopes: list[str]) -> str | None:
    if "openid" not in scopes:
        return None
    id_token, _, _ = key_manager.issue_jwt(
        subject=user.id,
        audience=client_id,
        token_type="id",
        scopes=scopes,
        ttl_seconds=settings.access_token_ttl_seconds,
        extra_claims={
            "email": user.email,
            "preferred_username": user.username,
            "tenant_id": user.tenant_id,
            "roles": user.roles,
        },
    )
    return id_token


@app.post("/auth/login", response_model=None)
async def login(payload: LoginRequest, request: Request):
    rate_limit_key = f"{payload.username}:{request.client.host if request.client else 'unknown'}"
    allowed, lockout_until = await platform_store.check_login_rate_limit(rate_limit_key)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Too many login attempts. Locked until {lockout_until}.")

    user = await platform_store.get_user_by_username(payload.username)
    client = await platform_store.get_client(payload.client_id)
    if not user or not client or payload.redirect_uri not in client.redirect_uris:
        await platform_store.register_failed_login(rate_limit_key)
        await platform_store.record_metric("login_failure_total")
        await write_audit("login.failed", "failure", None, payload.client_id, request.client.host if request.client else None, reason="invalid_principal_or_client")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.disabled or not verify_secret(payload.password, user.password_hash):
        await platform_store.register_failed_login(rate_limit_key)
        await platform_store.record_metric("login_failure_total")
        await write_audit("login.failed", "failure", user.id, payload.client_id, request.client.host if request.client else None, reason="bad_password_or_disabled")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    scopes = sorted(set(payload.scope.split()))
    risk_level, risk_reasons, trusted_device = await assess_login_risk(user, request, payload.device_fingerprint)
    mfa_required = user.mfa_enabled or risk_level == "high" or payload.prompt == "login"
    if mfa_required and (not payload.mfa_code or not user.mfa_secret or not verify_totp(user.mfa_secret, payload.mfa_code)):
        challenge = PendingMfaChallenge(
            challenge_id=str(uuid4()),
            user_id=user.id,
            client_id=payload.client_id,
            redirect_uri=payload.redirect_uri,
            scopes=scopes,
            code_challenge=payload.code_challenge,
            code_challenge_method=payload.code_challenge_method,
            expires_at=utc_now() + timedelta(seconds=settings.authorization_code_ttl_seconds),
            tenant_id=user.tenant_id,
            device_fingerprint_hash=fingerprint_hash(payload.device_fingerprint) if payload.device_fingerprint else None,
            ip_address=request.client.host if request.client else None,
            risk_level=risk_level,
        )
        await platform_store.register_pending_mfa(challenge, settings.authorization_code_ttl_seconds)
        await platform_store.record_metric("mfa_challenge_total")
        await write_audit(
            "login.mfa_challenge",
            "info",
            user.id,
            payload.client_id,
            request.client.host if request.client else None,
            risk_level=risk_level,
            risk_reasons=risk_reasons,
        )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "requires_mfa": True,
                "challenge_id": challenge.challenge_id,
                "risk_level": risk_level,
                "risk_reasons": risk_reasons,
            },
        )

    authorization_payload = await issue_authorization_code(
        user=user,
        client_id=payload.client_id,
        redirect_uri=payload.redirect_uri,
        scopes=scopes,
        code_challenge=payload.code_challenge,
        code_challenge_method=payload.code_challenge_method,
        risk_level=risk_level,
        trusted_device=trusted_device,
    )
    await platform_store.trust_device(user.id, payload.device_fingerprint, request.client.host if request.client else None)
    await platform_store.record_metric("login_success_total")
    await write_audit(
        "login.success",
        "success",
        user.id,
        payload.client_id,
        request.client.host if request.client else None,
        device_fingerprint_hash=fingerprint_hash(payload.device_fingerprint) if payload.device_fingerprint else None,
        risk_level=risk_level,
        risk_reasons=risk_reasons,
    )
    return authorization_payload


@app.post("/auth/mfa/verify")
async def verify_mfa(payload: MfaVerifyRequest) -> dict:
    challenge = await platform_store.consume_pending_mfa(payload.challenge_id)
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA challenge expired or invalid")
    user = await platform_store.get_user_by_id(challenge.user_id)
    if not user or not user.mfa_secret or not verify_totp(user.mfa_secret, payload.mfa_code):
        await platform_store.record_metric("login_failure_total")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA validation failed")

    await platform_store.trust_device_hash(user.id, challenge.device_fingerprint_hash, challenge.ip_address)
    await platform_store.record_metric("mfa_success_total")
    await write_audit("login.mfa_success", "success", user.id, challenge.client_id, challenge.ip_address, risk_level=challenge.risk_level)
    return await issue_authorization_code(
        user=user,
        client_id=challenge.client_id,
        redirect_uri=challenge.redirect_uri,
        scopes=challenge.scopes,
        code_challenge=challenge.code_challenge,
        code_challenge_method=challenge.code_challenge_method,
        risk_level=challenge.risk_level,
        trusted_device=bool(challenge.device_fingerprint_hash),
    )


@app.post("/auth/token")
async def token(payload: TokenRequest, response: Response, request: Request) -> dict:
    client = await platform_store.get_client(payload.client_id)
    if not client:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client")

    if payload.grant_type == "authorization_code":
        if "authorization_code" not in client.allowed_grants:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Grant not allowed")
        record = await platform_store.consume_auth_code(payload.code or "")
        if not record or record.client_id != payload.client_id or record.redirect_uri != payload.redirect_uri:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authorization code")
        if record.code_challenge:
            if not payload.code_verifier or pkce_challenge(payload.code_verifier) != record.code_challenge:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="PKCE validation failed")
        user = await platform_store.get_user_by_id(record.user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown user")

        access_token, _, _ = key_manager.issue_jwt(
            subject=user.id,
            audience="api-gateway",
            token_type="access",
            scopes=record.scopes,
            ttl_seconds=settings.access_token_ttl_seconds,
            extra_claims={
                "client_id": payload.client_id,
                "client_type": client.client_type,
                "roles": user.roles,
                "tenant_id": user.tenant_id,
                "department": user.department,
                "clearance_level": user.clearance_level,
                "risk_level": record.risk_level,
                "trusted_device": record.trusted_device,
            },
        )
        id_token = build_id_token(user, payload.client_id, record.scopes)
        refresh_token = random_token(48)
        family_id = str(uuid4())
        session_id = str(uuid4())
        refresh_session = RefreshSession(
            session_id=session_id,
            family_id=family_id,
            user_id=user.id,
            client_id=payload.client_id,
            token_hash=token_hash(refresh_token),
            csrf_token=record.csrf_token,
            expires_at=utc_now() + timedelta(seconds=settings.refresh_token_ttl_seconds),
            device_fingerprint=request.headers.get("X-Device-Fingerprint"),
            issued_ip=request.client.host if request.client else None,
            tenant_id=user.tenant_id,
            scopes=record.scopes,
            risk_level=record.risk_level,
            trusted_device=record.trusted_device,
        )
        await platform_store.register_refresh_session(refresh_token, refresh_session)
        await platform_store.record_metric("token_issued_total")
        response.set_cookie(
            settings.refresh_cookie_name,
            refresh_token,
            httponly=True,
            secure=settings.enforce_https_cookies,
            samesite="strict",
            max_age=settings.refresh_token_ttl_seconds,
        )
        response.set_cookie(
            settings.csrf_cookie_name,
            record.csrf_token,
            httponly=False,
            secure=settings.enforce_https_cookies,
            samesite="strict",
            max_age=settings.refresh_token_ttl_seconds,
        )
        token_response = build_token_response(access_token, refresh_token, record.csrf_token, settings.access_token_ttl_seconds, " ".join(record.scopes))
        if id_token:
            token_response["id_token"] = id_token
        return token_response

    if payload.grant_type == "client_credentials":
        if "client_credentials" not in client.allowed_grants or not payload.client_secret:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Grant not allowed")
        if not await platform_store.validate_client_secret(payload.client_id, payload.client_secret):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client secret")
        requested_scopes = sorted(set((payload.scope or "").split()) & set(client.scopes))
        if not requested_scopes:
            requested_scopes = client.scopes
        access_token, _, _ = key_manager.issue_jwt(
            subject=payload.client_id,
            audience=payload.audience or "api-gateway",
            token_type="access",
            scopes=requested_scopes,
            ttl_seconds=settings.access_token_ttl_seconds,
            extra_claims={"client_id": payload.client_id, "client_type": client.client_type, "roles": ["service"]},
        )
        await platform_store.record_metric("token_issued_total")
        return build_token_response(access_token, None, None, settings.access_token_ttl_seconds, " ".join(requested_scopes))

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported grant_type")


@app.post("/auth/refresh")
async def refresh(payload: RefreshRequest, response: Response, request: Request, csrf_token: str = Depends(require_csrf)) -> dict:
    refresh_token = payload.refresh_token or request.cookies.get(settings.refresh_cookie_name)
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required")
    session = await platform_store.get_refresh_session(refresh_token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalid")
    if session.revoked_at or session.rotated_at:
        await platform_store.revoke_refresh_family(session.family_id)
        await write_audit("refresh.replay_detected", "suspicious", session.user_id, session.client_id, request.client.host if request.client else None, family_id=session.family_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token replay detected")
    if session.csrf_token != csrf_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")

    user = await platform_store.get_user_by_id(session.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown principal")
    new_refresh_token = random_token(48)
    new_session = RefreshSession(
        session_id=str(uuid4()),
        family_id=session.family_id,
        user_id=session.user_id,
        client_id=session.client_id,
        token_hash=token_hash(new_refresh_token),
        csrf_token=session.csrf_token,
        expires_at=utc_now() + timedelta(seconds=settings.refresh_token_ttl_seconds),
        device_fingerprint=session.device_fingerprint,
        issued_ip=request.client.host if request.client else None,
        tenant_id=session.tenant_id,
        scopes=session.scopes,
        risk_level=session.risk_level,
        trusted_device=session.trusted_device,
    )
    await platform_store.rotate_refresh_session(refresh_token, new_refresh_token, new_session)
    access_token, _, _ = key_manager.issue_jwt(
        subject=user.id,
        audience="api-gateway",
        token_type="access",
        scopes=session.scopes,
        ttl_seconds=settings.access_token_ttl_seconds,
        extra_claims={
            "client_id": session.client_id,
            "client_type": "public",
            "roles": user.roles,
            "tenant_id": user.tenant_id,
            "department": user.department,
            "clearance_level": user.clearance_level,
            "risk_level": session.risk_level,
            "trusted_device": session.trusted_device,
        },
    )
    id_token = build_id_token(user, session.client_id, session.scopes)
    response.set_cookie(
        settings.refresh_cookie_name,
        new_refresh_token,
        httponly=True,
        secure=settings.enforce_https_cookies,
        samesite="strict",
        max_age=settings.refresh_token_ttl_seconds,
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        session.csrf_token,
        httponly=False,
        secure=settings.enforce_https_cookies,
        samesite="strict",
        max_age=settings.refresh_token_ttl_seconds,
    )
    await platform_store.record_metric("token_refreshed_total")
    token_response = build_token_response(access_token, new_refresh_token, session.csrf_token, settings.access_token_ttl_seconds, " ".join(session.scopes))
    if id_token:
        token_response["id_token"] = id_token
    return token_response


@app.post("/auth/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke(payload: RevokeRequest, request: Request, csrf_token: str = Depends(require_csrf)) -> Response:
    refresh_session = await platform_store.get_refresh_session(payload.token)
    if refresh_session:
        if refresh_session.csrf_token != csrf_token:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
        await platform_store.revoke_refresh_family(refresh_session.family_id)
        await write_audit("refresh.revoked", "success", refresh_session.user_id, refresh_session.client_id, request.client.host if request.client else None, family_id=refresh_session.family_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    try:
        token_payload = key_manager.verify_jwt(payload.token, "api-gateway")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported token") from exc
    await platform_store.revoke_access_jti(token_payload["jti"], max(token_payload["exp"] - int(utc_now().timestamp()), 1))
    await write_audit("access.revoked", "success", token_payload["sub"], token_payload.get("client_id"), request.client.host if request.client else None, jti=token_payload["jti"])
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict:
    return {
        "issuer": settings.issuer,
        "authorization_endpoint": f"{settings.auth_server_url}/auth/login",
        "token_endpoint": f"{settings.auth_server_url}/auth/token",
        "userinfo_endpoint": f"{settings.auth_server_url}/oidc/userinfo",
        "jwks_uri": f"{settings.auth_server_url}/.well-known/jwks.json",
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile:read", "offline_access"],
    }


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return {"keys": [key_manager.public_jwk()]}


@app.get("/oidc/userinfo")
async def userinfo(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    token_value = auth_header.split(" ", 1)[1]
    try:
        payload = key_manager.verify_jwt(token_value, "api-gateway")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    user = await platform_store.get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return {
        "sub": user.id,
        "email": user.email,
        "preferred_username": user.username,
        "tenant_id": user.tenant_id,
        "roles": user.roles,
    }


@app.get("/metrics")
async def metrics() -> dict:
    return await platform_store.get_metrics()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "auth-server"}
