# SentinelAuth

## Creator

This project was created and is maintained by **Anish Kumar**.

SentinelAuth is a production-style Zero Trust authentication and authorization platform implemented as a set of Python microservices. It includes:

- OAuth2 authorization server with Authorization Code, PKCE, refresh-token rotation, and client credentials.
- OpenID Connect discovery, JWKS publishing, `id_token` issuance, and `userinfo`.
- RSA-signed JWT access tokens with gateway validation and token revocation.
- RBAC plus ABAC policy enforcement.
- Service-to-service authentication for internal APIs.
- Risk-based authentication with device trust and step-up MFA challenges.
- Audit logging, security metrics, Docker, Kubernetes manifests, and test coverage for replay and tampering scenarios.

## Services

- `services/auth_server`: OAuth2 provider, token issuance, refresh, revocation, login throttling.
- `services/api_gateway`: validates JWTs on every request and applies Zero Trust policy decisions.
- `services/user_service`: protected user profile APIs and internal directory lookup.
- `services/policy_engine`: central RBAC + ABAC decision point.
- `services/audit_service`: append-only audit ingestion and retrieval for security operations.
- `shared`: key management, password hashing, JWT verification, policy logic, security middleware, bootstrap store.

## Sample bootstrap identities

Demo users are pre-seeded for local testing only:

- `alice / ChangeMe!123 / TOTP secret JBSWY3DPEHPK3PXP`
- `bob / ChangeMe!123`
- `carol / ChangeMe!123`

Local service and machine credentials come from environment variables in `.env`; use `.env.example` as the template and rotate all values before any non-local deployment.

## Quick start

1. Create `.env` from `.env.example`.
2. Install dependencies with `pip install -r requirements.txt`.
3. Start the stack with `docker compose up --build`.
4. Use the auth server on `http://localhost:8000` and gateway on `http://localhost:8004`.

## Example OAuth2 flow

1. `POST /auth/login` with `client_id=sentinel-web`, user credentials, redirect URI, PKCE challenge, and optional device fingerprint.
2. If risk is elevated, complete the step-up challenge at `POST /auth/mfa/verify`.
3. Exchange the authorization code at `POST /auth/token`.
4. Call `GET /user/profile` through the API gateway with the RSA-signed access token.
5. Refresh using `POST /auth/refresh` with the CSRF header and refresh cookie or body token.
6. Revoke using `POST /auth/revoke`.

## Testing

- `pytest`

## Security highlights

- Argon2 password hashing.
- Login rate limiting and lockouts.
- Short-lived access tokens and rotated refresh tokens.
- JWT revocation tracking.
- Device trust and contextual risk scoring.
- TOTP-based step-up MFA.
- CSRF protection for refresh and revoke.
- Security headers to reduce XSS and clickjacking risk.
- Audit events for failed logins, suspicious refresh reuse, and token revocation.

## Docs

- `docs/oauth2_flows.md`
- `docs/token_lifecycle.md`
- `docs/threat_model.md`
- `docs/security_tradeoffs.md`