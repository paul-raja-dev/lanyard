import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pwdlib import PasswordHash

from app.config import get_settings

password_hasher = PasswordHash.recommended()


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return password_hasher.verify(plain, hashed)


# ---------------------------------------------------------------------------
# Key loading & JWKS helpers
# ---------------------------------------------------------------------------


@lru_cache(maxsize=16)
def _load_private_key(key_path: Path) -> bytes:
    return key_path.read_bytes()


def get_active_signing_key() -> tuple[str, bytes]:
    """Return (kid, private_key_pem) for the currently configured active_key_id."""
    settings = get_settings()
    kid = settings.active_key_id
    candidate = settings.keys_dir / f"{kid}.private.pem"
    key_path = candidate if candidate.exists() else settings.private_key_path
    return kid, _load_private_key(key_path)


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _public_pem_to_jwk(kid: str, pem: bytes) -> dict:
    public_key = serialization.load_pem_public_key(pem)
    assert isinstance(public_key, rsa.RSAPublicKey)
    nums = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(nums.n),
        "e": _b64url_uint(nums.e),
    }


def build_jwks() -> dict:
    """Build JWKS from all *.public.pem files in keys_dir (with single-key fallback)."""
    settings = get_settings()
    keys: list[dict] = []

    if settings.keys_dir.is_dir():
        for pem_path in sorted(settings.keys_dir.glob("*.public.pem")):
            kid = pem_path.name.removesuffix(".public.pem")
            keys.append(_public_pem_to_jwk(kid, pem_path.read_bytes()))

    if not keys and settings.public_key_path.exists():
        keys.append(
            _public_pem_to_jwk(
                settings.active_key_id, settings.public_key_path.read_bytes()
            )
        )

    return {"keys": keys}


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def create_access_token(user_id: str, email: str, client_id: str) -> str:
    settings = get_settings()
    kid, private_key = get_active_signing_key()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "aud": client_id,
        "iss": settings.issuer,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# Refresh-token helpers
# ---------------------------------------------------------------------------


def generate_refresh_token() -> tuple[str, str]:
    """Return (raw_token, hashed_token).

    Send *raw_token* to the client; persist only *hashed_token* so a DB leak
    cannot hijack active sessions.
    """
    raw = secrets.token_urlsafe(48)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
