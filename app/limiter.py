from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings

settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.redis_url,
    enabled=settings.rate_limit_enabled,
    headers_enabled=True,
)


def get_login_email_key(request: Request) -> str:
    """Rate-limit key scoped to target email (populated by login middleware)."""
    email = getattr(request.state, "login_email", None)
    if email:
        return f"email:{email}"
    return get_remote_address(request)
