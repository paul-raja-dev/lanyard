import secrets

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import Application, get_db
from app.schemas import AppCreate, AppResponse

router = APIRouter(prefix="/apps", tags=["Applications"])


@router.post("", response_model=AppResponse, status_code=201)
def create_application(data: AppCreate, db: Session = Depends(get_db)):
    """Register a new client application and return its ``client_id``."""
    client_id = f"client_{secrets.token_urlsafe(12)}"
    app = Application(name=data.name, client_id=client_id)
    db.add(app)
    db.commit()
    db.refresh(app)
    return {"name": app.name, "client_id": app.client_id}
