from fastapi import Depends, FastAPI, HTTPException

from shared.config import get_settings
from shared.dependencies import build_subject_context, require_token
from shared.middleware import SecurityHeadersMiddleware
from shared.models import SubjectContext
from shared.policy import evaluate_policy
from shared.store import platform_store


settings = get_settings()
app = FastAPI(title="SentinelAuth API Gateway", version="1.0.0", docs_url="/docs" if settings.docs_enabled else None)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/user/profile")
async def user_profile(payload: dict = Depends(require_token("api-gateway"))) -> dict:
    subject = SubjectContext(**build_subject_context(payload))
    decision = evaluate_policy(subject, "user_profile", "read", resource_owner_id=payload["sub"])
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)
    user = await platform_store.get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "profile": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "tenant_id": user.tenant_id,
            "department": user.department,
            "clearance_level": user.clearance_level,
        },
        "policy": decision.model_dump(),
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "api-gateway"}
