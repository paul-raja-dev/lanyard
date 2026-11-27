"""
Generate an RSA-2048 key pair in the keys/ directory for multi-key JWKS rotation.

Usage:
    python scripts/generate_keys.py                  # generates keys/auth-key-1.*
    python scripts/generate_keys.py --kid auth-key-2 # generates keys/auth-key-2.*
"""

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keys(
    kid: str = "auth-key-1",
    keys_dir: Path = Path("keys"),
    key_size: int = 2048,
) -> tuple[Path, Path]:
    keys_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    private_path = keys_dir / f"{kid}.private.pem"
    public_path = keys_dir / f"{kid}.public.pem"

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(private_path, 0o600)

    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"Generated key pair '{kid}':")
    print(f"  Private: {private_path}")
    print(f"  Public : {public_path}")
    print(f"To activate for signing, set ACTIVE_KEY_ID={kid} in .env")
    return private_path, public_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA-2048 key pair for Lanyard JWKS")
    parser.add_argument("--kid", default="auth-key-1", help="Key ID (default: auth-key-1)")
    parser.add_argument("--keys-dir", type=Path, default=Path("keys"), help="Directory to store keys (default: keys)")
    parser.add_argument("--key-size", type=int, default=2048, help="RSA key size in bits (default: 2048)")
    args = parser.parse_args()

    generate_rsa_keys(kid=args.kid, keys_dir=args.keys_dir, key_size=args.key_size)
