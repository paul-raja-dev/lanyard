"""
Generate RSA-2048 key pair (private.pem / public.pem).

Usage:
    python scripts/generate_keys.py
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keys(
    private_path: str = "private.pem",
    public_path: str = "public.pem",
    key_size: int = 2048,
) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(public_path, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"Keys written to '{private_path}' and '{public_path}'")


if __name__ == "__main__":
    generate_rsa_keys()
