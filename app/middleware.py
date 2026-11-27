import logging
import time
import uuid

from fastapi import Request

from app.config import get_settings
from app.database import AuditLog, SessionLocal
from app.security import decode_access_token

logger = logging.getLogger("lanyard.audit")


def _extract_user_id(request: Request) -> str | None:
    """Best-effort extraction of user_id from Bearer JWT for audit attribution."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = decode_access_token(token)
        sub = payload.get("sub")
        return str(sub) if sub else None
    except Exception:
        return None


async def audit_log_middleware(request: Request, call_next):
    """Log every HTTP request to stdout and persist to PostgreSQL audit_logs."""
    settings = get_settings()
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    start = time.perf_counter()

    response = await call_next(request)

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id

    if not settings.audit_log_enabled:
        return response

    path = request.url.path
    method = request.method
    status_code = response.status_code
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    user_id = _extract_user_id(request)

    log_fn = logger.info
    if status_code >= 500:
        log_fn = logger.error
    elif status_code >= 400:
        log_fn = logger.warning

    log_fn(
        "%s %s -> %s (%.2fms) ip=%s user_id=%s req_id=%s",
        method,
        path,
        status_code,
        duration_ms,
        client_ip,
        user_id,
        request_id,
    )

    if path not in settings.audit_log_exclude_paths:
        db = SessionLocal()
        try:
            db.add(
                AuditLog(
                    request_id=request_id,
                    method=method,
                    path=path,
                    status_code=status_code,
                    client_ip=client_ip,
                    user_id=user_id,
                    user_agent=user_agent,
                    duration_ms=duration_ms,
                )
            )
            db.commit()
        except Exception:
            logger.exception("Failed to persist audit log for req_id=%s", request_id)
            db.rollback()
        finally:
            db.close()

    return response
