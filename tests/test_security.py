"""Unit tests for the cryptographic helpers, including their failure paths."""

from datetime import timedelta

import jwt
import pytest
from fastapi import HTTPException

from app.config import get_settings
from app.core import security
from app.core.security import (
    create_token,
    decode_token,
    decrypt_payload,
    encrypt_payload,
    hash_password,
    token_expiry,
    verify_password,
)

settings = get_settings()


class TestPasswordHashing:
    def test_hash_verifies_against_the_original(self):
        digest = hash_password("correct-horse-battery")

        assert digest.startswith("$argon2")
        assert verify_password("correct-horse-battery", digest)

    def test_wrong_password_does_not_verify(self):
        assert not verify_password("wrong", hash_password("correct-horse-battery"))

    def test_hashes_are_salted_and_therefore_unique(self):
        assert hash_password("same-password") != hash_password("same-password")

    def test_malformed_hash_is_rejected_rather_than_raising(self):
        assert not verify_password("anything", "not-a-valid-argon2-hash")


class TestPayloadEncryption:
    def test_round_trip_preserves_the_payload(self):
        payload = {"username": "member", "password": "secret", "notes": None}

        assert decrypt_payload(encrypt_payload(payload)) == payload

    def test_ciphertext_hides_the_plaintext(self):
        token = encrypt_payload({"username": None, "password": "hunter2", "notes": None})

        assert "hunter2" not in token

    def test_encryption_is_non_deterministic(self):
        payload = {"username": "a", "password": "b", "notes": "c"}

        assert encrypt_payload(payload) != encrypt_payload(payload)

    def test_tampered_ciphertext_raises_a_server_error(self):
        token = encrypt_payload({"username": "a", "password": "b", "notes": "c"})
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")

        with pytest.raises(HTTPException) as caught:
            decrypt_payload(tampered)
        assert caught.value.status_code == 500

    def test_garbage_input_raises_a_server_error(self):
        with pytest.raises(HTTPException) as caught:
            decrypt_payload("not-a-fernet-token")
        assert caught.value.status_code == 500

    def test_a_different_key_cannot_decrypt(self):
        token = encrypt_payload({"username": "a", "password": "b", "notes": "c"})

        from cryptography.fernet import Fernet

        with pytest.raises(HTTPException):
            original = security.settings.encryption_key
            security.settings.encryption_key = Fernet.generate_key().decode()
            try:
                decrypt_payload(token)
            finally:
                security.settings.encryption_key = original

    def test_an_invalid_configured_key_is_reported_clearly(self, monkeypatch):
        monkeypatch.setattr(security.settings, "encryption_key", "obviously-not-a-fernet-key")

        with pytest.raises(RuntimeError, match="valid Fernet key"):
            security._fernet()

    def test_missing_key_falls_back_to_a_derived_development_key(self, monkeypatch):
        """With no explicit key the service derives one from the JWT secret."""
        monkeypatch.setattr(security.settings, "encryption_key", None)

        assert decrypt_payload(encrypt_payload({"password": "derived"})) == {"password": "derived"}


class TestTokens:
    def test_create_and_decode_round_trip(self):
        token, jti = create_token("user-1", "access", timedelta(minutes=5))
        claims = decode_token(token, "access")

        assert claims["sub"] == "user-1"
        assert claims["type"] == "access"
        assert claims["jti"] == jti

    def test_each_token_gets_a_unique_identifier(self):
        _, first = create_token("user-1", "access", timedelta(minutes=5))
        _, second = create_token("user-1", "access", timedelta(minutes=5))

        assert first != second

    def test_an_explicit_identifier_is_honoured(self):
        _, jti = create_token("user-1", "refresh", timedelta(days=1), token_id="fixed-id")

        assert jti == "fixed-id"

    def test_wrong_type_is_rejected(self):
        token, _ = create_token("user-1", "refresh", timedelta(days=1))

        with pytest.raises(HTTPException) as caught:
            decode_token(token, "access")
        assert caught.value.status_code == 401

    def test_expired_token_is_rejected(self):
        token, _ = create_token("user-1", "access", timedelta(seconds=-30))

        with pytest.raises(HTTPException) as caught:
            decode_token(token, "access")
        assert caught.value.status_code == 401

    def test_token_signed_with_another_secret_is_rejected(self):
        forged = jwt.encode(
            {"sub": "user-1", "type": "access", "jti": "x"}, "an-entirely-different-secret"
        )

        with pytest.raises(HTTPException):
            decode_token(forged, "access")

    @pytest.mark.parametrize(
        "claims",
        [
            {"type": "access", "jti": "x"},
            {"sub": "user-1", "jti": "x"},
            {"sub": "user-1", "type": "access"},
        ],
        ids=["no-subject", "no-type", "no-jti"],
    )
    def test_tokens_missing_required_claims_are_rejected(self, claims):
        token = jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)

        with pytest.raises(HTTPException):
            decode_token(token, "access")

    def test_the_none_algorithm_is_not_accepted(self):
        """Guards against the classic 'alg: none' JWT bypass."""
        unsigned = jwt.encode({"sub": "user-1", "type": "access", "jti": "x"}, key="", algorithm="none")

        with pytest.raises(HTTPException):
            decode_token(unsigned, "access")

    def test_token_expiry_is_in_the_future(self):
        from datetime import UTC, datetime

        assert token_expiry(7) > datetime.now(UTC)
