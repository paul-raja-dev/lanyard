from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import Application, RefreshToken, User, get_db
from app.schemas import (
    MessageResponse,
    RefreshRequest,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)

settings = get_settings()
router = APIRouter(tags=["Auth"])


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register(data: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=data.email, hashed_password=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email}


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


@router.post("/login", response_model=TokenResponse, summary="Authenticate and get tokens")
def login(data: UserLogin, db: Session = Depends(get_db)):
    # 1. Validate client application
    app_record = (
        db.query(Application).filter(Application.client_id == data.client_id).first()
    )
    if not app_record:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # 2. Validate user credentials
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # 3. Issue tokens
    access_token = create_access_token(user.id, user.email, app_record.client_id)
    raw_refresh, hashed_refresh = generate_refresh_token()

    db.add(
        RefreshToken(
            token_hash=hashed_refresh,
            user_id=user.id,
            client_id=app_record.client_id,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "token_type": "Bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
    }


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


@router.post("/refresh", response_model=TokenResponse, summary="Rotate refresh token")
def refresh_tokens(data: RefreshRequest, db: Session = Depends(get_db)):
    hashed = hash_token(data.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed).first()

    if not stored or stored.revoked:
        raise HTTPException(status_code=401, detail="Invalid or revoked refresh token")

    if stored.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = db.query(User).filter(User.id == stored.user_id).first()

    # Rotate: revoke old, issue new
    stored.revoked = True
    access_token = create_access_token(user.id, user.email, stored.client_id)
    raw_refresh, hashed_refresh = generate_refresh_token()

    db.add(
        RefreshToken(
            token_hash=hashed_refresh,
            user_id=user.id,
            client_id=stored.client_id,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "token_type": "Bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
    }


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@router.post("/logout", response_model=MessageResponse, summary="Revoke a refresh token")
def logout(data: RefreshRequest, db: Session = Depends(get_db)):
    hashed = hash_token(data.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed).first()

    if stored and not stored.revoked:
        stored.revoked = True
        db.commit()

    return {"msg": "Logged out successfully"}
