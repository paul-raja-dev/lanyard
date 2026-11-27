import secrets

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import Application, get_db
from app.limiter import limiter
from app.schemas import AppCreate, AppResponse

settings = get_settings()
router = APIRouter(prefix="/apps", tags=["Applications"])


@router.post("", response_model=AppResponse, status_code=201)
@limiter.limit(settings.rate_limit_apps)
def create_application(
    request: Request,
    response: Response,
    data: AppCreate,
    db: Session = Depends(get_db),
):
    """Register a new client application and return its ``client_id``."""
    client_id = f"client_{secrets.token_urlsafe(12)}"
    app = Application(name=data.name, client_id=client_id)
    db.add(app)
    db.commit()
    db.refresh(app)
    return {"name": app.name, "client_id": app.client_id}
