from fastapi import Depends, FastAPI, HTTPException

from shared.config import get_settings
from shared.dependencies import require_service_token, require_token
from shared.middleware import SecurityHeadersMiddleware
from shared.store import platform_store


settings = get_settings()
app = FastAPI(title="SentinelAuth User Service", version="1.0.0", docs_url="/docs" if settings.docs_enabled else None)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/internal/users/{user_id}")
async def get_user_internal(user_id: str, _: dict = Depends(require_service_token("user-service"))) -> dict:
    user = await platform_store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "tenant_id": user.tenant_id,
        "department": user.department,
        "clearance_level": user.clearance_level,
    }


@app.get("/user/profile")
async def get_profile(payload: dict = Depends(require_token("api-gateway"))) -> dict:
    user = await platform_store.get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "tenant_id": user.tenant_id,
        "department": user.department,
        "clearance_level": user.clearance_level,
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "user-service"}
