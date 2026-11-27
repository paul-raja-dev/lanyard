"""
Create or promote a Lanyard admin user and ensure the internal admin client app exists.

Usage:
    python scripts/create_admin.py --email admin@lanyard.dev --password "..."
"""

import argparse
import sys
from pathlib import Path

# Allow running directly as `python scripts/create_admin.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings
from app.database import Application, SessionLocal, User
from app.security import hash_password


def create_or_promote_admin(email: str, password: str) -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        app_record = (
            db.query(Application)
            .filter(Application.client_id == settings.lanyard_admin_client_id)
            .first()
        )
        if not app_record:
            db.add(
                Application(
                    name="Lanyard Admin",
                    client_id=settings.lanyard_admin_client_id,
                )
            )

        user = db.query(User).filter(User.email == email).first()
        if user:
            user.is_admin = True
            if password:
                user.hashed_password = hash_password(password)
            action = "Promoted existing user to admin"
        else:
            user = User(
                email=email,
                hashed_password=hash_password(password),
                is_admin=True,
            )
            db.add(user)
            action = "Created admin user"

        db.commit()
        print(f"{action}: {email} (client_id={settings.lanyard_admin_client_id})")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create or promote a Lanyard admin user")
    parser.add_argument("--email", required=True, help="Admin email address")
    parser.add_argument("--password", required=True, help="Admin password")
    args = parser.parse_args()

    create_or_promote_admin(email=args.email, password=args.password)
