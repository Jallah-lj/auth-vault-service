"""Registration, login, token rotation, revocation and identity checks."""

import jwt
import pytest

from app.config import get_settings
from app.core.security import create_token
from app.db.models import RefreshToken, User

settings = get_settings()
VALID_PASSWORD = "correct-horse-battery"


class TestRegister:
    def test_returns_token_pair_and_profile(self, client):
        response = client.post(
            "/api/v1/auth/register",
            json={"email": "new@example.com", "password": VALID_PASSWORD},
        )

        assert response.status_code == 201
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"] and body["refresh_token"]
        assert body["user"]["email"] == "new@example.com"
        assert "password" not in body["user"]
        assert "password_hash" not in body["user"]

    def test_duplicate_email_conflicts(self, client, user):
        response = client.post(
            "/api/v1/auth/register",
            json={"email": user["email"], "password": VALID_PASSWORD},
        )

        assert response.status_code == 409

    def test_email_is_normalised_to_lowercase(self, client):
        created = client.post(
            "/api/v1/auth/register",
            json={"email": "Mixed.Case@Example.com", "password": VALID_PASSWORD},
        )
        assert created.status_code == 201
        assert created.json()["user"]["email"] == "mixed.case@example.com"

        # The same address in a different case must not create a second account.
        duplicate = client.post(
            "/api/v1/auth/register",
            json={"email": "mixed.case@example.com", "password": VALID_PASSWORD},
        )
        assert duplicate.status_code == 409

    def test_password_is_never_stored_in_plaintext(self, client, db_session):
        client.post(
            "/api/v1/auth/register",
            json={"email": "hashed@example.com", "password": VALID_PASSWORD},
        )

        stored = db_session.query(User).filter_by(email="hashed@example.com").one()
        assert stored.password_hash != VALID_PASSWORD
        assert stored.password_hash.startswith("$argon2")

    @pytest.mark.parametrize(
        "payload",
        [
            {"email": "not-an-email", "password": VALID_PASSWORD},
            {"email": "short@example.com", "password": "tooshort"},
            {"email": "missing-password@example.com"},
            {"password": VALID_PASSWORD},
        ],
        ids=["invalid-email", "password-too-short", "no-password", "no-email"],
    )
    def test_invalid_payloads_are_rejected(self, client, payload):
        assert client.post("/api/v1/auth/register", json=payload).status_code == 422


class TestLogin:
    def test_valid_credentials_issue_new_tokens(self, client, user):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user["email"], "password": user["password"]},
        )

        assert response.status_code == 200
        assert response.json()["refresh_token"] != user["refresh_token"]

    def test_login_is_case_insensitive_on_email(self, client, user):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user["email"].upper(), "password": user["password"]},
        )

        assert response.status_code == 200

    def test_wrong_password_is_unauthorised(self, client, user):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": user["email"], "password": "wrong-password-entry"},
        )

        assert response.status_code == 401

    def test_unknown_email_is_unauthorised_with_same_message(self, client, user):
        wrong_password = client.post(
            "/api/v1/auth/login",
            json={"email": user["email"], "password": "wrong-password-entry"},
        )
        unknown_user = client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": VALID_PASSWORD},
        )

        assert unknown_user.status_code == 401
        # Identical responses avoid leaking which accounts exist.
        assert unknown_user.json()["detail"] == wrong_password.json()["detail"]


class TestRefreshRotation:
    def test_refresh_returns_a_new_pair(self, client, user):
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": user["refresh_token"]}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["refresh_token"] != user["refresh_token"]
        assert body["access_token"] != user["access_token"]

    def test_rotated_token_is_revoked_in_the_database(self, client, user, db_session):
        claims = jwt.decode(
            user["refresh_token"], settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        client.post("/api/v1/auth/refresh", json={"refresh_token": user["refresh_token"]})

        assert db_session.get(RefreshToken, claims["jti"]).revoked_at is not None

    def test_reusing_a_rotated_token_is_rejected(self, client, user):
        first = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": user["refresh_token"]}
        )
        assert first.status_code == 200

        replay = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": user["refresh_token"]}
        )
        assert replay.status_code == 401

    def test_new_token_still_works_after_rotation(self, client, user):
        rotated = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": user["refresh_token"]}
        ).json()

        again = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
        )
        assert again.status_code == 200

    def test_access_token_cannot_be_used_to_refresh(self, client, user):
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": user["access_token"]}
        )

        assert response.status_code == 401

    def test_garbage_and_foreign_tokens_are_rejected(self, client):
        assert (
            client.post("/api/v1/auth/refresh", json={"refresh_token": "nonsense"}).status_code
            == 401
        )

        foreign = jwt.encode(
            {"sub": "someone", "type": "refresh", "jti": "abc"}, "a-different-secret"
        )
        assert (
            client.post("/api/v1/auth/refresh", json={"refresh_token": foreign}).status_code == 401
        )

    def test_unknown_but_correctly_signed_token_is_rejected(self, client, user):
        """A well-formed token with no matching database row must not be honoured."""
        from datetime import timedelta

        orphan, _ = create_token(user["id"], "refresh", timedelta(days=1))

        assert (
            client.post("/api/v1/auth/refresh", json={"refresh_token": orphan}).status_code == 401
        )


class TestLogout:
    def test_logout_revokes_the_refresh_token(self, client, user):
        assert (
            client.post(
                "/api/v1/auth/logout", json={"refresh_token": user["refresh_token"]}
            ).status_code
            == 204
        )

        after = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": user["refresh_token"]}
        )
        assert after.status_code == 401

    def test_logout_is_idempotent(self, client, user):
        client.post("/api/v1/auth/logout", json={"refresh_token": user["refresh_token"]})
        repeated = client.post(
            "/api/v1/auth/logout", json={"refresh_token": user["refresh_token"]}
        )

        assert repeated.status_code == 204

    def test_logout_rejects_a_malformed_token(self, client):
        response = client.post("/api/v1/auth/logout", json={"refresh_token": "nonsense"})

        assert response.status_code == 401

    def test_logout_does_not_revoke_another_users_session(self, client, users):
        alice = users.create()
        bob = users.create()

        client.post("/api/v1/auth/logout", json={"refresh_token": alice["refresh_token"]})

        still_valid = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": bob["refresh_token"]}
        )
        assert still_valid.status_code == 200


class TestMe:
    def test_returns_the_authenticated_profile(self, client, user):
        response = client.get("/api/v1/auth/me", headers=user["headers"])

        assert response.status_code == 200
        body = response.json()
        assert body["email"] == user["email"]
        assert body["id"] == user["id"]
        assert "password_hash" not in body

    def test_requires_a_token(self, client):
        assert client.get("/api/v1/auth/me").status_code == 401

    @pytest.mark.parametrize(
        "header",
        [
            {"Authorization": "Bearer nonsense"},
            {"Authorization": "Basic abc123"},
            {"Authorization": "Bearer "},
        ],
        ids=["malformed-jwt", "wrong-scheme", "empty-token"],
    )
    def test_rejects_bad_authorisation_headers(self, client, header):
        assert client.get("/api/v1/auth/me", headers=header).status_code == 401

    def test_refresh_token_is_not_accepted_as_an_access_token(self, client, user):
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {user['refresh_token']}"},
        )

        assert response.status_code == 401

    def test_token_for_a_deleted_user_is_rejected(self, client, user, db_session):
        db_session.delete(db_session.get(User, user["id"]))
        db_session.commit()

        response = client.get("/api/v1/auth/me", headers=user["headers"])
        assert response.status_code == 401


class TestSessionsAfterAccountRemoval:
    def test_refresh_fails_once_the_account_is_gone(self, client, user, db_session):
        """Deleting the user cascades to their refresh tokens, so rotation stops."""
        db_session.delete(db_session.get(User, user["id"]))
        db_session.commit()

        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": user["refresh_token"]}
        )
        assert response.status_code == 401
