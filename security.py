import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
import jwt
from pwdlib import PasswordHash

PRIVATE_KEY = Path("private.pem").read_bytes()
KEY_ID = "auth-key-1"  
ISSUER = "http://localhost:8000"

password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hasher.verify(plain_password, hashed_password)


def create_access_token(user_id: str, email: str, client_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,          
        "email": email,
        "aud": client_id,        
        "iss": ISSUER,           
        "iat": now,             
        "exp": now + timedelta(minutes=15), 
    }
    return jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def generate_refresh_token() -> tuple[str, str]:
    """
    Returns (raw_token, hashed_token).
    Send raw_token to the user; store hashed_token in the DB so even a DB leak can't hijack sessions.
    """
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()
