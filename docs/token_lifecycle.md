# Token Lifecycle

Documentation for SentinelAuth by **Anish Kumar**.

## Access token

- Issued by the auth server as an RSA-signed JWT.
- Contains `iss`, `sub`, `aud`, `jti`, `scope`, `typ`, and subject attributes for policy checks.
- Lifetime defaults to 5 minutes to minimize replay value.
- Validated at the API gateway and on internal services.
- Revoked by storing `jti` in the token store until expiry.

## Refresh token

- Opaque, high-entropy token stored only as a SHA-256 hash in the token store.
- Bound to a refresh session family and paired with a CSRF token.
- Rotated on every `POST /auth/refresh`.
- Reuse of an already rotated token triggers replay detection and revokes the whole family.

## Authorization code

- Short-lived and single-use.
- Bound to `client_id`, `redirect_uri`, tenant, and optional PKCE challenge.
- Deleted on redemption.

## Revocation model

- Refresh token revocation operates on the full family to stop reuse chains.
- Access token revocation tracks `jti` until expiration.
- Gateway and services deny revoked or expired tokens before business logic executes.