from shared.config import get_settings
from shared.dependencies import key_manager
from shared.security import verify_secret
from shared.store import platform_store


settings = get_settings()


async def issue_service_token(subject: str, audience: str, secret: str, scopes: list[str]) -> str:
    client = await platform_store.get_client(subject)
    if not client or client.client_type != "service" or not client.client_secret_hash:
        raise ValueError("Unknown service client")
    if not verify_secret(secret, client.client_secret_hash):
        raise ValueError("Invalid service secret")
    token, _, _ = key_manager.issue_jwt(
        subject=subject,
        audience=audience,
        token_type="access",
        scopes=scopes,
        ttl_seconds=settings.access_token_ttl_seconds,
        extra_claims={"client_id": subject, "client_type": "service", "roles": ["service"]},
    )
    return token
