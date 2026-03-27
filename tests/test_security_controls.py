def test_token_tampering_is_rejected(auth_client, gateway_client):
    login_response = auth_client.post(
        "/auth/login",
        json={
            "username": "bob",
            "password": "ChangeMe!123",
            "client_id": "sentinel-web",
            "redirect_uri": "https://app.sentinel.local/callback",
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
        },
    )
    assert token_response.status_code == 200
    valid_token = token_response.json()["access_token"]
    tampered_token = f"{valid_token[:-1]}{'A' if valid_token[-1] != 'A' else 'B'}"

    response = gateway_client.get("/user/profile", headers={"Authorization": f"Bearer {tampered_token}"})
    assert response.status_code == 401


def test_login_rate_limiting_blocks_repeated_failures(auth_client):
    last_response = None
    for _ in range(5):
        last_response = auth_client.post(
            "/auth/login",
            json={
                "username": "bob",
                "password": "DefinitelyWrong123",
                "client_id": "sentinel-web",
                "redirect_uri": "https://app.sentinel.local/callback",
            },
        )
    assert last_response is not None
    assert last_response.status_code == 401

    blocked_response = auth_client.post(
        "/auth/login",
        json={
            "username": "bob",
            "password": "DefinitelyWrong123",
            "client_id": "sentinel-web",
            "redirect_uri": "https://app.sentinel.local/callback",
        },
    )
    assert blocked_response.status_code == 429


def test_oidc_metadata_and_jwks_are_exposed(auth_client):
    metadata_response = auth_client.get("/.well-known/openid-configuration")
    assert metadata_response.status_code == 200
    metadata = metadata_response.json()
    assert metadata["jwks_uri"].endswith("/.well-known/jwks.json")

    jwks_response = auth_client.get("/.well-known/jwks.json")
    assert jwks_response.status_code == 200
    assert jwks_response.json()["keys"][0]["kid"] == "sentinel-rsa-1"
