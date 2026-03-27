import base64
import binascii
import hmac
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from shared.config import Settings


password_hasher = PasswordHasher()


def utc_now() -> datetime:
    return datetime.now(UTC)


def hash_secret(secret: str) -> str:
    return password_hasher.hash(secret)


def verify_secret(secret: str, secret_hash: str) -> bool:
    try:
        return password_hasher.verify(secret_hash, secret)
    except VerifyMismatchError:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def random_token(size: int = 48) -> str:
    return secrets.token_urlsafe(size)


def fingerprint_hash(fingerprint: str) -> str:
    return token_hash(fingerprint)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def _base32_decode(secret: str) -> bytes:
    normalized = secret.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def generate_totp(secret: str, for_time: int | None = None, period: int = 30, digits: int = 6) -> str:
    timestamp = int(for_time or utc_now().timestamp())
    counter = timestamp // period
    key = _base32_decode(secret)
    counter_bytes = counter.to_bytes(8, "big")
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
    return str(code % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    try:
        current_ts = int(utc_now().timestamp())
        for offset in range(-window, window + 1):
            if generate_totp(secret, for_time=current_ts + (offset * 30)) == code:
                return True
        return False
    except (ValueError, TypeError, binascii.Error):
        return False


class KeyManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        private_pem, public_pem = self._resolve_keys()
        self._private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
        self._public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        self.private_pem = private_pem
        self.public_pem = public_pem

    def _resolve_keys(self) -> tuple[str, str]:
        if self.settings.private_key_pem and self.settings.public_key_pem:
            return self.settings.private_key_pem, self.settings.public_key_pem
        if self.settings.is_production:
            raise RuntimeError("Production mode requires RSA keys via SENTINELAUTH_PRIVATE_KEY_PEM and SENTINELAUTH_PUBLIC_KEY_PEM.")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return private_pem, public_pem

    def issue_jwt(
        self,
        *,
        subject: str,
        audience: str,
        token_type: str,
        scopes: list[str],
        ttl_seconds: int,
        extra_claims: dict[str, Any] | None = None,
    ) -> tuple[str, str, datetime]:
        issued_at = utc_now()
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        jti = str(uuid4())
        payload = {
            "iss": self.settings.issuer,
            "sub": subject,
            "aud": audience,
            "iat": int(issued_at.timestamp()),
            "nbf": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": jti,
            "scope": " ".join(sorted(set(scopes))),
            "typ": token_type,
        }
        if extra_claims:
            payload.update(extra_claims)
        token = jwt.encode(payload, self.private_pem, algorithm="RS256", headers={"kid": "sentinel-rsa-1"})
        return token, jti, expires_at

    def verify_jwt(self, token: str, audience: str) -> dict[str, Any]:
        return jwt.decode(
            token,
            self.public_pem,
            algorithms=["RS256"],
            audience=audience,
            issuer=self.settings.issuer,
            options={"require": ["exp", "iat", "nbf", "jti", "sub", "aud", "iss", "typ"]},
        )

    def public_jwk(self) -> dict[str, str]:
        public_numbers = self._public_key.public_numbers()
        n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")
        e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")
        return {"kty": "RSA", "use": "sig", "kid": "sentinel-rsa-1", "alg": "RS256", "n": n, "e": e}
