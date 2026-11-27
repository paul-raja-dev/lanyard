import base64
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI

from app.config import get_settings
from app.database import init_db
from app.routes import apps, auth
from app.schemas import MessageResponse

settings = get_settings()


# ---------------------------------------------------------------------------
# JWKS helper
# ---------------------------------------------------------------------------


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _build_jwks() -> dict:
    pem = settings.public_key_path.read_bytes()
    public_key = serialization.load_pem_public_key(pem)
    assert isinstance(public_key, rsa.RSAPublicKey)
    nums = public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": settings.key_id,
                "n": _b64url_uint(nums.n),
                "e": _b64url_uint(nums.e),
            }
        ]
    }


JWKS = _build_jwks()


# ---------------------------------------------------------------------------
# App factory / lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        lifespan=lifespan,
    )

    # Routers
    application.include_router(auth.router)
    application.include_router(apps.router)

    # System / discovery endpoints
    @application.get("/health", response_model=MessageResponse, tags=["System"])
    def health_check():
        return {"msg": "Healthy and connection is good"}

    @application.get("/.well-known/jwks.json", tags=["System"])
    def get_jwks():
        return JWKS

    return application


app = create_app()
