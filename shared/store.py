import asyncio
import logging
from collections import defaultdict
from datetime import timedelta

from redis import asyncio as redis

from shared.config import get_settings
from shared.models import AuditEvent, AuthorizationCodeRecord, OAuthClient, PendingMfaChallenge, RefreshSession, UserRecord
from shared.security import fingerprint_hash, hash_secret, token_hash, utc_now, verify_secret


logger = logging.getLogger(__name__)


class PlatformStore:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._lock = asyncio.Lock()
        self.redis = None if self.settings.redis_url == "memory://" else redis.from_url(self.settings.redis_url, decode_responses=True)
        self.users: dict[str, UserRecord] = {}
        self.users_by_username: dict[str, UserRecord] = {}
        self.oauth_clients: dict[str, OAuthClient] = {}
        self.auth_codes: dict[str, AuthorizationCodeRecord] = {}
        self.refresh_sessions: dict[str, RefreshSession] = {}
        self.refresh_index: dict[str, str] = {}
        self.revoked_access_jtis: dict[str, int] = {}
        self.rate_limits: dict[str, list[int]] = defaultdict(list)
        self.lockouts: dict[str, int] = {}
        self.metrics: dict[str, int] = defaultdict(int)
        self.audit_events: list[AuditEvent] = []
        self.pending_mfa: dict[str, PendingMfaChallenge] = {}
        self.known_devices: dict[str, set[str]] = defaultdict(set)
        self.last_seen_ip: dict[str, str] = {}
        self._seed()

    def _seed(self) -> None:
        if self.users:
            return
        admin = UserRecord(
            id="user-admin-1",
            username="alice",
            email="alice@example.com",
            password_hash=hash_secret("ChangeMe!123"),
            roles=["admin", "security_admin"],
            tenant_id="tenant-alpha",
            department="security",
            clearance_level=5,
            mfa_enabled=True,
            mfa_secret="JBSWY3DPEHPK3PXP",
        )
        engineer = UserRecord(
            id="user-eng-1",
            username="bob",
            email="bob@example.com",
            password_hash=hash_secret("ChangeMe!123"),
            roles=["user"],
            tenant_id="tenant-alpha",
            department="engineering",
            clearance_level=2,
        )
        support = UserRecord(
            id="user-support-1",
            username="carol",
            email="carol@example.com",
            password_hash=hash_secret("ChangeMe!123"),
            roles=["support"],
            tenant_id="tenant-alpha",
            department="support",
            clearance_level=3,
        )
        for user in (admin, engineer, support):
            self.users[user.id] = user
            self.users_by_username[user.username] = user

        self.oauth_clients[self.settings.web_client_id] = OAuthClient(
            client_id=self.settings.web_client_id,
            allowed_grants=["authorization_code", "refresh_token"],
            redirect_uris=[self.settings.web_redirect_uri],
            scopes=["openid", "profile:read", "offline_access"],
            client_type="public",
        )
        self.oauth_clients[self.settings.machine_client_id] = OAuthClient(
            client_id=self.settings.machine_client_id,
            client_secret_hash=hash_secret(self.settings.machine_client_secret),
            allowed_grants=["client_credentials"],
            scopes=["service.read", "profile:read"],
            client_type="confidential",
        )
        self.oauth_clients["api-gateway"] = OAuthClient(
            client_id="api-gateway",
            client_secret_hash=hash_secret(self.settings.gateway_service_secret),
            allowed_grants=["client_credentials"],
            scopes=["internal.user.read", "internal.policy.evaluate", "internal.audit.write"],
            client_type="service",
        )
        self.oauth_clients["audit-service"] = OAuthClient(
            client_id="audit-service",
            client_secret_hash=hash_secret(self.settings.audit_service_secret),
            allowed_grants=["client_credentials"],
            scopes=["internal.audit.write"],
            client_type="service",
        )
        self.oauth_clients["policy-engine"] = OAuthClient(
            client_id="policy-engine",
            client_secret_hash=hash_secret(self.settings.policy_service_secret),
            allowed_grants=["client_credentials"],
            scopes=["internal.policy.evaluate"],
            client_type="service",
        )
        self.oauth_clients["user-service"] = OAuthClient(
            client_id="user-service",
            client_secret_hash=hash_secret(self.settings.user_service_secret),
            allowed_grants=["client_credentials"],
            scopes=["internal.user.read"],
            client_type="service",
        )

    async def record_metric(self, name: str, value: int = 1) -> None:
        if self.redis:
            await self.redis.hincrby("metrics", name, value)
            return
        async with self._lock:
            self.metrics[name] += value

    async def get_metrics(self) -> dict[str, int]:
        if self.redis:
            data = await self.redis.hgetall("metrics")
            return {key: int(value) for key, value in data.items()}
        async with self._lock:
            return dict(self.metrics)

    async def record_audit_event(self, event: AuditEvent) -> None:
        if self.redis:
            await self.redis.rpush("audit_events", event.model_dump_json())
            await self.redis.ltrim("audit_events", -1000, -1)
        else:
            async with self._lock:
                self.audit_events.append(event)
        if event.status in {"failure", "suspicious"}:
            logger.warning("audit_event=%s actor=%s details=%s", event.event_type, event.actor_id, event.details)

    async def recent_audit_events(self, limit: int = 100) -> list[AuditEvent]:
        if self.redis:
            entries = await self.redis.lrange("audit_events", -limit, -1)
            return [AuditEvent.model_validate_json(entry) for entry in entries]
        async with self._lock:
            return list(self.audit_events[-limit:])

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        async with self._lock:
            return self.users_by_username.get(username)

    async def get_user_by_id(self, user_id: str) -> UserRecord | None:
        async with self._lock:
            return self.users.get(user_id)

    async def get_client(self, client_id: str) -> OAuthClient | None:
        async with self._lock:
            return self.oauth_clients.get(client_id)

    async def validate_client_secret(self, client_id: str, client_secret: str) -> bool:
        client = await self.get_client(client_id)
        if not client or not client.client_secret_hash:
            return False
        return verify_secret(client_secret, client.client_secret_hash)

    async def register_pending_mfa(self, challenge: PendingMfaChallenge, ttl_seconds: int) -> None:
        if self.redis:
            await self.redis.setex(f"mfa_challenge:{challenge.challenge_id}", ttl_seconds, challenge.model_dump_json())
            return
        async with self._lock:
            self.pending_mfa[challenge.challenge_id] = challenge

    async def consume_pending_mfa(self, challenge_id: str) -> PendingMfaChallenge | None:
        if self.redis:
            key = f"mfa_challenge:{challenge_id}"
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.get(key)
                pipe.delete(key)
                data, _ = await pipe.execute()
            return PendingMfaChallenge.model_validate_json(data) if data else None
        async with self._lock:
            challenge = self.pending_mfa.pop(challenge_id, None)
        if challenge and challenge.expires_at >= utc_now():
            return challenge
        return None

    async def is_known_device(self, user_id: str, raw_fingerprint: str | None) -> bool:
        if not raw_fingerprint:
            return False
        hashed = fingerprint_hash(raw_fingerprint)
        if self.redis:
            return bool(await self.redis.sismember(f"user_devices:{user_id}", hashed))
        async with self._lock:
            return hashed in self.known_devices[user_id]

    async def trust_device(self, user_id: str, raw_fingerprint: str | None, ip_address: str | None) -> None:
        if self.redis:
            if raw_fingerprint:
                await self.redis.sadd(f"user_devices:{user_id}", fingerprint_hash(raw_fingerprint))
            if ip_address:
                await self.redis.set(f"user_last_ip:{user_id}", ip_address)
            return
        async with self._lock:
            if raw_fingerprint:
                self.known_devices[user_id].add(fingerprint_hash(raw_fingerprint))
            if ip_address:
                self.last_seen_ip[user_id] = ip_address

    async def trust_device_hash(self, user_id: str, hashed_fingerprint: str | None, ip_address: str | None) -> None:
        if self.redis:
            if hashed_fingerprint:
                await self.redis.sadd(f"user_devices:{user_id}", hashed_fingerprint)
            if ip_address:
                await self.redis.set(f"user_last_ip:{user_id}", ip_address)
            return
        async with self._lock:
            if hashed_fingerprint:
                self.known_devices[user_id].add(hashed_fingerprint)
            if ip_address:
                self.last_seen_ip[user_id] = ip_address

    async def get_last_seen_ip(self, user_id: str) -> str | None:
        if self.redis:
            return await self.redis.get(f"user_last_ip:{user_id}")
        async with self._lock:
            return self.last_seen_ip.get(user_id)

    async def register_auth_code(self, code: str, record: AuthorizationCodeRecord) -> None:
        if self.redis:
            await self.redis.setex(
                f"auth_code:{token_hash(code)}",
                self.settings.authorization_code_ttl_seconds,
                record.model_dump_json(),
            )
            return
        async with self._lock:
            self.auth_codes[token_hash(code)] = record

    async def consume_auth_code(self, code: str) -> AuthorizationCodeRecord | None:
        code_id = token_hash(code)
        if self.redis:
            key = f"auth_code:{code_id}"
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.get(key)
                pipe.delete(key)
                data, _ = await pipe.execute()
            return AuthorizationCodeRecord.model_validate_json(data) if data else None
        async with self._lock:
            record = self.auth_codes.pop(code_id, None)
        if record and record.expires_at >= utc_now():
            return record
        return None

    async def register_refresh_session(self, refresh_token: str, session: RefreshSession) -> None:
        refresh_id = token_hash(refresh_token)
        if self.redis:
            ttl = int((session.expires_at - utc_now()).total_seconds())
            await self.redis.setex(f"refresh_session:{session.session_id}", ttl, session.model_dump_json())
            await self.redis.setex(f"refresh_index:{refresh_id}", ttl, session.session_id)
            await self.redis.sadd(f"refresh_family:{session.family_id}", session.session_id)
            await self.redis.expire(f"refresh_family:{session.family_id}", ttl)
            return
        async with self._lock:
            self.refresh_sessions[session.session_id] = session
            self.refresh_index[refresh_id] = session.session_id

    async def get_refresh_session(self, refresh_token: str) -> RefreshSession | None:
        refresh_id = token_hash(refresh_token)
        if self.redis:
            session_id = await self.redis.get(f"refresh_index:{refresh_id}")
            if not session_id:
                return None
            data = await self.redis.get(f"refresh_session:{session_id}")
            return RefreshSession.model_validate_json(data) if data else None
        async with self._lock:
            session_id = self.refresh_index.get(refresh_id)
            if not session_id:
                return None
            session = self.refresh_sessions.get(session_id)
        if not session:
            return None
        if session.expires_at < utc_now():
            return None
        if session.revoked_at:
            return session
        return session

    async def rotate_refresh_session(self, old_refresh_token: str, new_refresh_token: str, new_session: RefreshSession) -> RefreshSession | None:
        old_session = await self.get_refresh_session(old_refresh_token)
        if not old_session:
            return None
        if self.redis:
            old_session.rotated_at = utc_now()
            old_session.replaced_by = new_session.session_id
            old_ttl = max(int((old_session.expires_at - utc_now()).total_seconds()), 1)
            new_ttl = max(int((new_session.expires_at - utc_now()).total_seconds()), 1)
            await self.redis.setex(f"refresh_session:{old_session.session_id}", old_ttl, old_session.model_dump_json())
            await self.redis.setex(f"refresh_session:{new_session.session_id}", new_ttl, new_session.model_dump_json())
            await self.redis.setex(f"refresh_index:{token_hash(new_refresh_token)}", new_ttl, new_session.session_id)
            await self.redis.sadd(f"refresh_family:{new_session.family_id}", new_session.session_id)
            await self.redis.expire(f"refresh_family:{new_session.family_id}", new_ttl)
            return old_session
        async with self._lock:
            old_session.rotated_at = utc_now()
            old_session.replaced_by = new_session.session_id
            self.refresh_sessions[old_session.session_id] = old_session
            self.refresh_sessions[new_session.session_id] = new_session
            self.refresh_index[token_hash(new_refresh_token)] = new_session.session_id
        return old_session

    async def revoke_refresh_family(self, family_id: str) -> None:
        if self.redis:
            session_ids = await self.redis.smembers(f"refresh_family:{family_id}")
            for session_id in session_ids:
                data = await self.redis.get(f"refresh_session:{session_id}")
                if not data:
                    continue
                session = RefreshSession.model_validate_json(data)
                if not session.revoked_at:
                    session.revoked_at = utc_now()
                    ttl = max(int((session.expires_at - utc_now()).total_seconds()), 1)
                    await self.redis.setex(f"refresh_session:{session_id}", ttl, session.model_dump_json())
            return
        async with self._lock:
            for session in self.refresh_sessions.values():
                if session.family_id == family_id and not session.revoked_at:
                    session.revoked_at = utc_now()

    async def revoke_access_jti(self, jti: str, expires_in_seconds: int) -> None:
        if self.redis:
            await self.redis.setex(f"revoked_access:{jti}", expires_in_seconds, "1")
            return
        async with self._lock:
            self.revoked_access_jtis[jti] = int((utc_now() + timedelta(seconds=expires_in_seconds)).timestamp())

    async def is_access_revoked(self, jti: str) -> bool:
        if self.redis:
            return bool(await self.redis.exists(f"revoked_access:{jti}"))
        now_ts = int(utc_now().timestamp())
        async with self._lock:
            expired = [key for key, expiry in self.revoked_access_jtis.items() if expiry < now_ts]
            for key in expired:
                self.revoked_access_jtis.pop(key, None)
            return jti in self.revoked_access_jtis

    async def check_login_rate_limit(self, key: str) -> tuple[bool, int | None]:
        now_ts = int(utc_now().timestamp())
        if self.redis:
            lockout_ttl = await self.redis.ttl(f"login_lockout:{key}")
            if lockout_ttl and lockout_ttl > 0:
                return False, now_ts + lockout_ttl
            attempts = await self.redis.get(f"login_failures:{key}")
            return int(attempts or "0") < self.settings.login_max_attempts, None
        async with self._lock:
            if self.lockouts.get(key, 0) > now_ts:
                return False, self.lockouts[key]
            window_start = now_ts - self.settings.login_rate_limit_window_seconds
            attempts = [ts for ts in self.rate_limits[key] if ts > window_start]
            self.rate_limits[key] = attempts
            return len(attempts) < self.settings.login_max_attempts, None

    async def register_failed_login(self, key: str) -> int:
        now_ts = int(utc_now().timestamp())
        if self.redis:
            failures_key = f"login_failures:{key}"
            failures = await self.redis.incr(failures_key)
            if failures == 1:
                await self.redis.expire(failures_key, self.settings.login_rate_limit_window_seconds)
            if failures >= self.settings.login_max_attempts:
                await self.redis.setex(
                    f"login_lockout:{key}",
                    self.settings.login_rate_limit_window_seconds,
                    str(now_ts + self.settings.login_rate_limit_window_seconds),
                )
                return now_ts + self.settings.login_rate_limit_window_seconds
            return 0
        async with self._lock:
            self.rate_limits[key].append(now_ts)
            if len(self.rate_limits[key]) >= self.settings.login_max_attempts:
                lockout_until = now_ts + self.settings.login_rate_limit_window_seconds
                self.lockouts[key] = lockout_until
                return lockout_until
            return 0


platform_store = PlatformStore()
