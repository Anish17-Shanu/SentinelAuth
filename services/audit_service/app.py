from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from shared.config import get_settings
from shared.dependencies import require_service_token
from shared.middleware import SecurityHeadersMiddleware
from shared.models import AuditEvent
from shared.security import utc_now
from shared.store import platform_store


settings = get_settings()
app = FastAPI(title="SentinelAuth Audit Service", version="1.0.0", docs_url="/docs" if settings.docs_enabled else None)
app.add_middleware(SecurityHeadersMiddleware)


class AuditIngestRequest(BaseModel):
    event_type: str
    actor_id: str | None = None
    client_id: str | None = None
    ip_address: str | None = None
    status: str
    details: dict = Field(default_factory=dict)


@app.post("/internal/audit/events")
async def ingest(payload: AuditIngestRequest, _: dict = Depends(require_service_token("audit-service"))) -> dict:
    event = AuditEvent(
        event_type=payload.event_type,
        actor_id=payload.actor_id,
        client_id=payload.client_id,
        ip_address=payload.ip_address,
        status=payload.status,
        details=payload.details,
        created_at=utc_now(),
    )
    await platform_store.record_audit_event(event)
    return {"status": "accepted"}


@app.get("/internal/audit/events")
async def list_events(_: dict = Depends(require_service_token("audit-service"))) -> list[dict]:
    return [event.model_dump(mode="json") for event in await platform_store.recent_audit_events()]


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "audit-service"}
