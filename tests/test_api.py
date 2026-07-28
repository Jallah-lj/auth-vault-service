import os
import tempfile
from pathlib import Path

fd, db_path = tempfile.mkstemp(suffix=".sqlite")
os.close(fd)
os.environ["AUTH_VAULT_DATABASE_URL"] = f"sqlite:///{db_path}"
os.environ["AUTH_VAULT_JWT_SECRET"] = "test-jwt-secret-that-is-long-enough"

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402


def test_auth_and_vault_item_lifecycle():
    with TestClient(app) as client:
        registered = client.post("/api/v1/auth/register", json={"email": "member@example.com", "password": "correct-horse-battery"})
        assert registered.status_code == 201
        token = registered.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        created = client.post("/api/v1/vault/items", headers=headers, json={
            "title": "Example", "url": "https://example.com", "username": "member", "password": "secret", "notes": "private"
        })
        assert created.status_code == 201
        item = created.json()
        assert item["password"] == "secret"

        listed = client.get("/api/v1/vault/items", headers=headers)
        assert listed.status_code == 200
        assert listed.json()[0]["title"] == "Example"
        assert "password" not in listed.json()[0]

        changed = client.patch(f"/api/v1/vault/items/{item['id']}", headers=headers, json={"password": "new-secret"})
        assert changed.status_code == 200
        assert changed.json()["password"] == "new-secret"

        assert client.delete(f"/api/v1/vault/items/{item['id']}", headers=headers).status_code == 204


if __name__ == "__main__":
    Path(db_path).unlink(missing_ok=True)
