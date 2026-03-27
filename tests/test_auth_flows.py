from shared.security import generate_totp, pkce_challenge


def test_authorization_code_profile_and_rotating_refresh(auth_client, gateway_client):
    verifier = "verifier-value-1234567890"
    login_response = auth_client.post(
        "/auth/login",
        json={
            "username": "bob",
            "password": "ChangeMe!123",
            "client_id": "sentinel-web",
            "redirect_uri": "https://app.sentinel.local/callback",
            "scope": "openid profile:read offline_access",
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    assert login_response.status_code == 200
    authorization_code = login_response.json()["authorization_code"]

    token_response = auth_client.post(
        "/auth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "sentinel-web",
            "code": authorization_code,
            "redirect_uri": "https://app.sentinel.local/callback",
            "code_verifier": verifier,
        },
    )
    assert token_response.status_code == 200
    token_payload = token_response.json()
    access_token = token_payload["access_token"]
    old_refresh_token = token_payload["refresh_token"]
    csrf_token = token_payload["csrf_token"]

    profile_response = gateway_client.get("/user/profile", headers={"Authorization": f"Bearer {access_token}"})
    assert profile_response.status_code == 200
    assert profile_response.json()["profile"]["username"] == "bob"

    refresh_response = auth_client.post(
        "/auth/refresh",
        json={"refresh_token": old_refresh_token},
        headers={"X-CSRF-Token": csrf_token},
        cookies={"sentinel_csrf": csrf_token},
    )
    assert refresh_response.status_code == 200
    new_refresh_token = refresh_response.json()["refresh_token"]
    assert new_refresh_token != old_refresh_token

    replay_response = auth_client.post(
        "/auth/refresh",
        json={"refresh_token": old_refresh_token},
        headers={"X-CSRF-Token": csrf_token},
        cookies={"sentinel_csrf": csrf_token},
    )
    assert replay_response.status_code == 401
    assert "replay" in replay_response.json()["detail"].lower()


def test_client_credentials_for_service_to_service_access(auth_client, user_client):
    token_response = auth_client.post(
        "/auth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": "api-gateway",
            "client_secret": "dev-gateway-secret",
            "audience": "user-service",
            "scope": "internal.user.read",
        },
    )
    assert token_response.status_code == 200
    access_token = token_response.json()["access_token"]

    internal_response = user_client.get(
        "/internal/users/user-eng-1",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert internal_response.status_code == 200
    assert internal_response.json()["username"] == "bob"


def test_high_risk_login_requires_mfa_and_returns_oidc_tokens(auth_client):
    login_response = auth_client.post(
        "/auth/login",
        json={
            "username": "alice",
            "password": "ChangeMe!123",
            "client_id": "sentinel-web",
            "redirect_uri": "https://app.sentinel.local/callback",
            "scope": "openid profile:read offline_access",
            "device_fingerprint": "brand-new-admin-device",
        },
    )
    assert login_response.status_code == 202
    challenge_id = login_response.json()["challenge_id"]

    verify_response = auth_client.post(
        "/auth/mfa/verify",
        json={"challenge_id": challenge_id, "mfa_code": generate_totp("JBSWY3DPEHPK3PXP")},
    )
    assert verify_response.status_code == 200
    authorization_code = verify_response.json()["authorization_code"]
    assert verify_response.json()["risk_level"] == "high"

    token_response = auth_client.post(
        "/auth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "sentinel-web",
            "code": authorization_code,
            "redirect_uri": "https://app.sentinel.local/callback",
        },
    )
    assert token_response.status_code == 200
    body = token_response.json()
    assert "id_token" in body
    assert body["access_token"]

    userinfo_response = auth_client.get(
        "/oidc/userinfo",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert userinfo_response.status_code == 200
    assert userinfo_response.json()["preferred_username"] == "alice"
