import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_settings

settings = get_settings()

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------


class Application(Base):
    __tablename__ = "applications"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    client_id = Column(String, unique=True, index=True, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String, primary_key=True, default=_uuid)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    client_id = Column(String, ForeignKey("applications.client_id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)

    # Token family — links all tokens in one login session chain
    family_id = Column(String, index=True, nullable=False, default=_uuid)
    # SHA-256 hash of the parent token (None for the root/login token)
    parent_hash = Column(String, nullable=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Safety-net: create tables if they don't exist (Alembic is authoritative)."""
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
