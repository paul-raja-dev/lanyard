import base64
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session

from database import Application, RefreshToken, User, get_db, init_db
from schemas import (
    AppCreate,
    AppResponse,
    MessageResponse,
    RefreshRequest,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from security import (
    KEY_ID,
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _build_jwks() -> dict:
    pem = Path("public.pem").read_bytes()
    public_key = serialization.load_pem_public_key(pem)
    assert isinstance(public_key, rsa.RSAPublicKey)
    numbers = public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }


JWKS = _build_jwks()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # Creates lanyard.db tables on startup
    yield


app = FastAPI(title="Lanyard Auth Service", lifespan=lifespan)


# --- System & Discovery Endpoints ---
@app.get("/health", response_model=MessageResponse)
def health_check():
    return {"msg": "Healthy and connection is good"}


@app.get("/.well-known/jwks.json")
def get_jwks():
    return JWKS


# --- Application & Auth Endpoints ---
@app.post("/apps", response_model=AppResponse, status_code=status.HTTP_201_CREATED)
def create_application(data: AppCreate, db: Session = Depends(get_db)):
    """Registers a new client application."""
    client_id = f"client_{secrets.token_urlsafe(12)}"
    new_app = Application(name=data.name, client_id=client_id)
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return {"name": new_app.name, "client_id": new_app.client_id}


@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(data: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=data.email, hashed_password=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email}


@app.post("/login", response_model=TokenResponse)
def login(data: UserLogin, db: Session = Depends(get_db)):
    # 1. Verify the client_id belongs to a registered app
    app_record = db.query(Application).filter(Application.client_id == data.client_id).first()
    if not app_record:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # 2. Verify user credentials
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # 3. Mint RS256 Access Token & Refresh Token
    access_token = create_access_token(user.id, user.email, app_record.client_id)
    raw_refresh, hashed_refresh = generate_refresh_token()

    db_refresh = RefreshToken(
        token_hash=hashed_refresh,
        user_id=user.id,
        client_id=app_record.client_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(db_refresh)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "token_type": "Bearer",
        "expires_in": 900,
    }


@app.post("/refresh", response_model=TokenResponse)
def refresh_tokens(data: RefreshRequest, db: Session = Depends(get_db)):
    hashed = hash_token(data.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed).first()

    if not stored or stored.revoked:
        raise HTTPException(status_code=401, detail="Invalid or revoked refresh token")

    expires_at = stored.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = db.query(User).filter(User.id == stored.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Rotate refresh token (revoke old one, issue a brand new pair)
    stored.revoked = True
    new_raw_refresh, new_hashed_refresh = generate_refresh_token()
    db.add(
        RefreshToken(
            token_hash=new_hashed_refresh,
            user_id=user.id,
            client_id=stored.client_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
    )
    db.commit()

    new_access_token = create_access_token(user.id, user.email, stored.client_id)
    return {
        "access_token": new_access_token,
        "refresh_token": new_raw_refresh,
        "token_type": "Bearer",
        "expires_in": 900,
    }


@app.post("/logout", response_model=MessageResponse)
def logout(data: RefreshRequest, db: Session = Depends(get_db)):
    hashed = hash_token(data.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed).first()
    if stored:
        stored.revoked = True
        db.commit()
    return {"msg": "Logged out successfully"}
