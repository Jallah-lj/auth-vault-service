from datetime import timedelta

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.dependencies import CurrentUser, DbSession
from app.config import get_settings
from app.core.security import create_token, decode_token, hash_password, token_expiry, verify_password
from app.db.models import RefreshToken, User
from app.schemas.auth import AuthResponse, LoginRequest, RefreshRequest, TokenPair, RegisterRequest, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


def issue_tokens(db: DbSession, user: User) -> TokenPair:
    access, _ = create_token(user.id, "access", timedelta(minutes=settings.access_token_minutes))
    refresh, refresh_id = create_token(user.id, "refresh", timedelta(days=settings.refresh_token_days))
    db.add(RefreshToken(id=refresh_id, user_id=user.id, expires_at=token_expiry(settings.refresh_token_days)))
    return TokenPair(access_token=access, refresh_token=refresh)


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: DbSession):
    email = str(payload.email).lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    db.flush()
    tokens = issue_tokens(db, user)
    db.commit()
    db.refresh(user)
    return AuthResponse(user=user, **tokens.model_dump())


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, db: DbSession):
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    tokens = issue_tokens(db, user)
    db.commit()
    return AuthResponse(user=user, **tokens.model_dump())


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, db: DbSession):
    claims = decode_token(payload.refresh_token, "refresh")
    token = db.get(RefreshToken, claims["jti"])
    if not token or token.user_id != claims["sub"] or token.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")
    token.revoked_at = token.created_at  # only a non-null marker is required; avoids clock inconsistencies.
    user = db.get(User, token.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    tokens = issue_tokens(db, user)
    db.commit()
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: RefreshRequest, db: DbSession):
    claims = decode_token(payload.refresh_token, "refresh")
    token = db.get(RefreshToken, claims["jti"])
    if token and token.user_id == claims["sub"] and token.revoked_at is None:
        token.revoked_at = token.created_at
        db.commit()


@router.get("/me", response_model=UserResponse)
def me(current_user: CurrentUser):
    return current_user
