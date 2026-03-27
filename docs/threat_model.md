# Threat Model

Documentation for SentinelAuth by **ANISH KUMAR**.

## Token theft

- Mitigations:
- Short-lived access tokens.
- Refresh token hashing in the store.
- HttpOnly refresh cookie support.
- Audience-bound JWTs and revocation checks.
- Residual risk:
- Compromised endpoints can still exfiltrate active access tokens during their short lifetime.

## Replay attack

- Mitigations:
- Refresh token rotation on every use.
- Replay detection when an old refresh token is reused.
- Revocation of the entire refresh family after suspicious reuse.
- PKCE for authorization code exchange.
- ID tokens are audience-bound to the relying client.

## Brute force and credential stuffing

- Mitigations:
- Argon2 password hashing.
- Per-identity login throttling and lockout windows.
- MFA support for sensitive users.
- Audit events for failed logins and MFA failures.

## Internal trust abuse

- Mitigations:
- No implicit trust between services.
- Service JWTs require audience validation and `client_type=service`.
- Policy decisions are centralized and explicit.

## Device spoofing and anomalous sign-in context

- Mitigations:
- Device fingerprint hashing and trust tracking.
- Contextual risk scoring from new device, IP shift, and privilege level.
- Step-up TOTP MFA for risky or privileged logins.

## XSS and CSRF

- Mitigations:
- Strict security headers.
- CSRF token validation for refresh and revoke.
- Recommended client pattern is in-memory access token plus HttpOnly refresh cookie.
