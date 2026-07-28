"""Shared pytest configuration and fixtures.

Environment variables must be set before importing anything from ``app``:
``app.config``, ``app.db.database`` and ``app.core.security`` all resolve
settings at import time (and ``get_settings`` is ``lru_cache``d), so a late
override would be silently ignored.
"""

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

from cryptography.fernet import Fernet

_EXISTING_DB = os.environ.get("AUTH_VAULT_TEST_DB_PATH")
if _EXISTING_DB:
    # pytest imports this file as the top-level ``conftest`` module, but an
    # explicit ``from tests.conftest import ...`` creates a *second* module
    # object and re-executes it. Reusing the recorded path keeps both copies
    # pointed at one database and avoids leaking a temp file per import.
    _DB_PATH = _EXISTING_DB
else:
    _DB_FD, _DB_PATH = tempfile.mkstemp(suffix=".sqlite")
    os.close(_DB_FD)
    os.environ["AUTH_VAULT_TEST_DB_PATH"] = _DB_PATH
    os.environ["AUTH_VAULT_DATABASE_URL"] = f"sqlite:///{_DB_PATH}"
    os.environ["AUTH_VAULT_JWT_SECRET"] = "test-jwt-secret-that-is-long-enough"
    # Pin an explicit Fernet key so tests never depend on the
    # jwt-secret-derived development fallback.
    os.environ["AUTH_VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402

VALID_PASSWORD = "correct-horse-battery"


@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    """A TestClient whose lifespan creates the schema once per session."""
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()
    Path(_DB_PATH).unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def clean_tables(client: TestClient) -> Iterator[None]:
    """Truncate every table after each test so cases stay independent."""
    yield
    with SessionLocal() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()


@pytest.fixture
def db_session() -> Iterator[object]:
    """Direct database access, for asserting on data at rest."""
    with SessionLocal() as session:
        yield session


class UserFactory:
    """Registers users and hands back their tokens and auth headers."""

    def __init__(self, test_client: TestClient) -> None:
        self._client = test_client
        self._count = 0

    def create(self, email: str | None = None, password: str = VALID_PASSWORD) -> dict:
        if email is None:
            self._count += 1
            email = f"member{self._count}@example.com"
        response = self._client.post(
            "/api/v1/auth/register", json={"email": email, "password": password}
        )
        assert response.status_code == 201, response.text
        body = response.json()
        return {
            "email": email,
            "password": password,
            "id": body["user"]["id"],
            "access_token": body["access_token"],
            "refresh_token": body["refresh_token"],
            "headers": {"Authorization": f"Bearer {body['access_token']}"},
        }


@pytest.fixture
def users(client: TestClient) -> UserFactory:
    return UserFactory(client)


@pytest.fixture
def user(users: UserFactory) -> dict:
    return users.create()


@pytest.fixture
def auth_headers(user: dict) -> dict[str, str]:
    return user["headers"]
