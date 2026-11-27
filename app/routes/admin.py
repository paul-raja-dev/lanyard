from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import AuditLog, get_db
from app.dependencies import require_admin
from app.schemas import AuditLogListResponse

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)


@router.get("/logs", response_model=AuditLogListResponse, summary="Query audit logs")
def get_audit_logs(
    method: str | None = Query(default=None),
    path: str | None = Query(default=None),
    status_code: int | None = Query(default=None),
    user_id: str | None = Query(default=None),
    client_ip: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Return paginated HTTP request/audit logs (Lanyard admin only)."""
    query = db.query(AuditLog)

    if method:
        query = query.filter(AuditLog.method == method.upper())
    if path:
        query = query.filter(AuditLog.path == path)
    if status_code is not None:
        query = query.filter(AuditLog.status_code == status_code)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if client_ip:
        query = query.filter(AuditLog.client_ip == client_ip)

    total = query.count()
    items = (
        query.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }
