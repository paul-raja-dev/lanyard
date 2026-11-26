import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI

app = FastAPI()

KEY_ID = "auth-key-1"


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _build_jwks() -> dict:
    pem = Path("public.pem").read_bytes()
    public_key = serialization.load_pem_public_key(pem)
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


JWKS = _build_jwks()  # computed once at startup


@app.get("/health")
def health_check():
    return {"msg": "Healthy and connection is good"}


@app.get("/.well-known/jwks.json")
def get_jwks():
    return JWKS