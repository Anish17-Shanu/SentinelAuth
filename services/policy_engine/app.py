from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from shared.config import get_settings
from shared.dependencies import require_service_token
from shared.middleware import SecurityHeadersMiddleware
from shared.models import SubjectContext
from shared.policy import evaluate_policy


settings = get_settings()
app = FastAPI(title="SentinelAuth Policy Engine", version="1.0.0", docs_url="/docs" if settings.docs_enabled else None)
app.add_middleware(SecurityHeadersMiddleware)


class PolicyRequest(BaseModel):
    subject_id: str
    roles: list[str] = Field(default_factory=list)
    tenant_id: str
    scopes: list[str] = Field(default_factory=list)
    attributes: dict = Field(default_factory=dict)
    resource: str
    action: str
    resource_owner_id: str | None = None


@app.post("/internal/policies/evaluate")
async def evaluate(payload: PolicyRequest, _: dict = Depends(require_service_token("policy-engine"))) -> dict:
    decision = evaluate_policy(
        SubjectContext(
            subject_id=payload.subject_id,
            roles=payload.roles,
            tenant_id=payload.tenant_id,
            attributes=payload.attributes,
            scopes=payload.scopes,
        ),
        payload.resource,
        payload.action,
        payload.resource_owner_id,
    )
    return decision.model_dump()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "policy-engine"}
