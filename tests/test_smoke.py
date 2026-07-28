"""Service-level checks and the end-to-end happy path.

The lifecycle test below is the successor to the original ``test_api.py``.
"""


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_schema_is_served(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/vault/items" in paths


def test_unknown_route_is_not_found(client):
    assert client.get("/api/v1/nope").status_code == 404


def test_full_register_store_and_logout_journey(client):
    """Register, store a credential, rotate the session, then log out."""
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": "journey@example.com", "password": "correct-horse-battery"},
    )
    assert registered.status_code == 201
    session = registered.json()
    headers = {"Authorization": f"Bearer {session['access_token']}"}

    created = client.post(
        "/api/v1/vault/items",
        headers=headers,
        json={
            "title": "Example",
            "url": "https://example.com/",
            "username": "member",
            "password": "secret",
            "notes": "private",
        },
    )
    assert created.status_code == 201
    item = created.json()
    assert item["password"] == "secret"

    listed = client.get("/api/v1/vault/items", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["title"] == "Example"
    assert "password" not in listed.json()[0]

    changed = client.patch(
        f"/api/v1/vault/items/{item['id']}", headers=headers, json={"password": "new-secret"}
    )
    assert changed.status_code == 200
    assert changed.json()["password"] == "new-secret"

    # Rotate the session and confirm the fresh access token still works.
    rotated = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": session["refresh_token"]}
    )
    assert rotated.status_code == 200
    new_headers = {"Authorization": f"Bearer {rotated.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=new_headers).status_code == 200

    assert (
        client.delete(f"/api/v1/vault/items/{item['id']}", headers=new_headers).status_code == 204
    )

    logged_out = client.post(
        "/api/v1/auth/logout", json={"refresh_token": rotated.json()["refresh_token"]}
    )
    assert logged_out.status_code == 204
