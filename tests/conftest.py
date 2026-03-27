from collections import defaultdict

import pytest
from fastapi.testclient import TestClient

from services.api_gateway.app import app as gateway_app
from services.auth_server.app import app as auth_app
from services.user_service.app import app as user_app
from shared.store import platform_store


@pytest.fixture(autouse=True)
def reset_store_state():
    platform_store.auth_codes.clear()
    platform_store.refresh_sessions.clear()
    platform_store.refresh_index.clear()
    platform_store.revoked_access_jtis.clear()
    platform_store.rate_limits.clear()
    platform_store.lockouts.clear()
    platform_store.metrics = defaultdict(int)
    platform_store.audit_events.clear()
    platform_store.pending_mfa.clear()
    platform_store.known_devices.clear()
    platform_store.last_seen_ip.clear()
    yield


@pytest.fixture
def auth_client():
    with TestClient(auth_app) as client:
        yield client


@pytest.fixture
def gateway_client():
    with TestClient(gateway_app) as client:
        yield client


@pytest.fixture
def user_client():
    with TestClient(user_app) as client:
        yield client
