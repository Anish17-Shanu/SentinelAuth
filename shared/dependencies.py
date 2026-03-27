import logging
from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from shared.config import get_settings
from shared.security import KeyManager
from shared.store import platform_store


logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)
settings = get_settings()
key_manager = KeyManager(settings)


def build_subject_context(payload: dict) -> dict:
    return {
        "subject_id": payload["sub"],
        "roles": payload.get("roles", []),
        "tenant_id": payload.get("tenant_id", ""),
        "attributes": {
            "department": payload.get("department"),
            "clearance_level": payload.get("clearance_level", 1),
            "risk_level": payload.get("risk_level", "low"),
        },
        "scopes": payload.get("scope", "").split(),
    }


def _auth_error(detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail)


def require_token(audience: str) -> Callable:
    async def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict:
        if not credentials:
            raise _auth_error("Bearer token required")
        try:
            payload = key_manager.verify_jwt(credentials.credentials, audience)
        except Exception as exc:
            logger.warning("token_validation_failed audience=%s error=%s", audience, exc)
            raise _auth_error("Invalid or expired token") from exc
        if await platform_store.is_access_revoked(payload["jti"]):
            raise _auth_error("Token has been revoked")
        request.state.token_payload = payload
        return payload

    return dependency


def require_service_token(audience: str) -> Callable:
    async def dependency(payload: dict = Depends(require_token(audience))) -> dict:
        if payload.get("typ") != "access":
            raise _auth_error("Access token required")
        if payload.get("client_type") != "service":
            raise _auth_error("Service identity required", status.HTTP_403_FORBIDDEN)
        return payload

    return dependency


async def require_csrf(
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> str:
    cookie_value = request.cookies.get(settings.csrf_cookie_name)
    if not x_csrf_token or not cookie_value or cookie_value != x_csrf_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return x_csrf_token
