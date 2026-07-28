"""Vault CRUD, cross-user isolation and encryption-at-rest guarantees."""

import json

import pytest

from app.db.models import VaultItem

ITEM = {
    "title": "Example",
    "url": "https://example.com/",
    "username": "member",
    "password": "secret",
    "notes": "private",
}


def create_item(client, headers, **overrides):
    payload = {**ITEM, **overrides}
    response = client.post("/api/v1/vault/items", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


class TestCreate:
    def test_returns_the_decrypted_item(self, client, auth_headers):
        item = create_item(client, auth_headers)

        assert item["title"] == ITEM["title"]
        assert item["url"] == ITEM["url"]
        assert item["username"] == ITEM["username"]
        assert item["password"] == ITEM["password"]
        assert item["notes"] == ITEM["notes"]
        assert item["id"] and item["created_at"] and item["updated_at"]

    def test_secret_fields_are_optional(self, client, auth_headers):
        response = client.post(
            "/api/v1/vault/items", headers=auth_headers, json={"title": "Title only"}
        )

        assert response.status_code == 201
        body = response.json()
        assert body["username"] is None
        assert body["password"] is None
        assert body["notes"] is None
        assert body["url"] is None

    def test_requires_authentication(self, client):
        assert client.post("/api/v1/vault/items", json=ITEM).status_code == 401

    @pytest.mark.parametrize(
        "payload",
        [{}, {"title": ""}, {"title": "x" * 201}, {"title": "ok", "url": "not-a-url"}],
        ids=["no-title", "empty-title", "title-too-long", "invalid-url"],
    )
    def test_invalid_payloads_are_rejected(self, client, auth_headers, payload):
        response = client.post("/api/v1/vault/items", headers=auth_headers, json=payload)

        assert response.status_code == 422


class TestEncryptionAtRest:
    def test_secrets_are_not_readable_in_the_database(self, client, auth_headers, db_session):
        create_item(client, auth_headers)

        stored = db_session.query(VaultItem).one()
        blob = stored.encrypted_data
        assert ITEM["password"] not in blob
        assert ITEM["username"] not in blob
        assert ITEM["notes"] not in blob
        with pytest.raises(ValueError):
            json.loads(blob)

    def test_title_and_url_remain_queryable_metadata(self, client, auth_headers, db_session):
        create_item(client, auth_headers)

        stored = db_session.query(VaultItem).one()
        assert stored.title == ITEM["title"]
        assert stored.url == ITEM["url"]


class TestList:
    def test_returns_metadata_without_secrets(self, client, auth_headers):
        create_item(client, auth_headers)

        response = client.get("/api/v1/vault/items", headers=auth_headers)

        assert response.status_code == 200
        entry = response.json()[0]
        assert entry["title"] == ITEM["title"]
        for secret in ("username", "password", "notes"):
            assert secret not in entry

    def test_is_empty_for_a_new_account(self, client, auth_headers):
        assert client.get("/api/v1/vault/items", headers=auth_headers).json() == []

    def test_only_returns_items_owned_by_the_caller(self, client, users):
        alice, bob = users.create(), users.create()
        create_item(client, alice["headers"], title="Alice item")
        create_item(client, bob["headers"], title="Bob item")

        titles = [
            entry["title"] for entry in client.get("/api/v1/vault/items", headers=alice["headers"]).json()
        ]
        assert titles == ["Alice item"]

    def test_requires_authentication(self, client):
        assert client.get("/api/v1/vault/items").status_code == 401


class TestRetrieve:
    def test_returns_the_decrypted_item(self, client, auth_headers):
        created = create_item(client, auth_headers)

        response = client.get(f"/api/v1/vault/items/{created['id']}", headers=auth_headers)

        assert response.status_code == 200
        assert response.json()["password"] == ITEM["password"]

    def test_unknown_id_is_not_found(self, client, auth_headers):
        response = client.get("/api/v1/vault/items/does-not-exist", headers=auth_headers)

        assert response.status_code == 404

    def test_requires_authentication(self, client, auth_headers):
        created = create_item(client, auth_headers)

        assert client.get(f"/api/v1/vault/items/{created['id']}").status_code == 401


class TestUpdate:
    def test_updates_a_single_secret_field(self, client, auth_headers):
        created = create_item(client, auth_headers)

        response = client.patch(
            f"/api/v1/vault/items/{created['id']}",
            headers=auth_headers,
            json={"password": "new-secret"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["password"] == "new-secret"
        # Untouched secrets must survive the re-encryption round trip.
        assert body["username"] == ITEM["username"]
        assert body["notes"] == ITEM["notes"]

    def test_updates_metadata(self, client, auth_headers):
        created = create_item(client, auth_headers)

        response = client.patch(
            f"/api/v1/vault/items/{created['id']}",
            headers=auth_headers,
            json={"title": "Renamed", "url": "https://renamed.example.com/"},
        )

        assert response.status_code == 200
        assert response.json()["title"] == "Renamed"
        assert response.json()["url"] == "https://renamed.example.com/"

    def test_empty_patch_leaves_the_item_unchanged(self, client, auth_headers):
        created = create_item(client, auth_headers)

        response = client.patch(
            f"/api/v1/vault/items/{created['id']}", headers=auth_headers, json={}
        )

        assert response.status_code == 200
        assert response.json()["password"] == ITEM["password"]
        assert response.json()["title"] == ITEM["title"]

    def test_secrets_can_be_cleared(self, client, auth_headers):
        created = create_item(client, auth_headers)

        response = client.patch(
            f"/api/v1/vault/items/{created['id']}", headers=auth_headers, json={"notes": None}
        )

        assert response.status_code == 200
        assert response.json()["notes"] is None

    def test_unknown_id_is_not_found(self, client, auth_headers):
        response = client.patch(
            "/api/v1/vault/items/does-not-exist", headers=auth_headers, json={"title": "x"}
        )

        assert response.status_code == 404

    def test_invalid_payload_is_rejected(self, client, auth_headers):
        created = create_item(client, auth_headers)

        response = client.patch(
            f"/api/v1/vault/items/{created['id']}", headers=auth_headers, json={"title": ""}
        )

        assert response.status_code == 422


class TestDelete:
    def test_removes_the_item(self, client, auth_headers):
        created = create_item(client, auth_headers)

        assert (
            client.delete(f"/api/v1/vault/items/{created['id']}", headers=auth_headers).status_code
            == 204
        )
        assert (
            client.get(f"/api/v1/vault/items/{created['id']}", headers=auth_headers).status_code
            == 404
        )

    def test_deleting_twice_is_not_found(self, client, auth_headers):
        created = create_item(client, auth_headers)
        client.delete(f"/api/v1/vault/items/{created['id']}", headers=auth_headers)

        assert (
            client.delete(f"/api/v1/vault/items/{created['id']}", headers=auth_headers).status_code
            == 404
        )

    def test_requires_authentication(self, client, auth_headers):
        created = create_item(client, auth_headers)

        assert client.delete(f"/api/v1/vault/items/{created['id']}").status_code == 401


class TestCrossUserIsolation:
    """Another account's item must be indistinguishable from one that does not exist."""

    @pytest.fixture
    def other_users_item(self, client, users):
        owner = users.create()
        intruder = users.create()
        return create_item(client, owner["headers"], title="Owner secret"), intruder

    def test_cannot_read(self, client, other_users_item):
        item, intruder = other_users_item

        response = client.get(f"/api/v1/vault/items/{item['id']}", headers=intruder["headers"])

        assert response.status_code == 404
        assert "Owner secret" not in response.text

    def test_cannot_update(self, client, other_users_item):
        item, intruder = other_users_item

        response = client.patch(
            f"/api/v1/vault/items/{item['id']}",
            headers=intruder["headers"],
            json={"password": "hijacked"},
        )

        assert response.status_code == 404

    def test_cannot_delete(self, client, other_users_item):
        item, intruder = other_users_item

        assert (
            client.delete(
                f"/api/v1/vault/items/{item['id']}", headers=intruder["headers"]
            ).status_code
            == 404
        )

    def test_owner_still_has_an_intact_item(self, client, users):
        owner = users.create()
        intruder = users.create()
        item = create_item(client, owner["headers"])

        client.patch(
            f"/api/v1/vault/items/{item['id']}",
            headers=intruder["headers"],
            json={"password": "hijacked"},
        )
        client.delete(f"/api/v1/vault/items/{item['id']}", headers=intruder["headers"])

        survivor = client.get(f"/api/v1/vault/items/{item['id']}", headers=owner["headers"])
        assert survivor.status_code == 200
        assert survivor.json()["password"] == ITEM["password"]

    def test_a_missing_and_a_forbidden_item_look_identical(self, client, other_users_item):
        item, intruder = other_users_item

        forbidden = client.get(f"/api/v1/vault/items/{item['id']}", headers=intruder["headers"])
        missing = client.get("/api/v1/vault/items/does-not-exist", headers=intruder["headers"])

        assert forbidden.status_code == missing.status_code
        assert forbidden.json() == missing.json()
