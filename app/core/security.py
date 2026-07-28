import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status

from app.config import get_settings

password_hasher = PasswordHasher()
settings = get_settings()


def _fernet() -> Fernet:
    key = settings.encryption_key
    if not key:
        # Convenient locally; deployments must provide a separate, persistent encryption key.
        key = base64.urlsafe_b64encode(hashlib.sha256(settings.jwt_secret.encode()).digest()).decode()
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("AUTH_VAULT_ENCRYPTION_KEY must be a valid Fernet key") from exc


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except Exception:
        return False


def encrypt_payload(payload: dict[str, str | None]) -> str:
    return _fernet().encrypt(json.dumps(payload, separators=(",", ":")).encode()).decode()


def decrypt_payload(value: str) -> dict[str, str | None]:
    try:
        return json.loads(_fernet().decrypt(value.encode()).decode())
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Unable to decrypt vault item") from exc


def create_token(subject: str, token_type: str, expires_delta: timedelta, token_id: str | None = None) -> tuple[str, str]:
    now = datetime.now(UTC)
    jti = token_id or str(uuid4())
    payload = {"sub": subject, "type": token_type, "jti": jti, "iat": now, "exp": now + expires_delta}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm), jti


def decode_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc
    if payload.get("type") != expected_type or not payload.get("sub") or not payload.get("jti"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload


def token_expiry(days: int) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)
