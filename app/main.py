import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.database import init_db
from app.limiter import limiter
from app.routes import apps, auth
from app.schemas import MessageResponse
from app.security import build_jwks

settings = get_settings()


# ---------------------------------------------------------------------------
# App factory / lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        lifespan=lifespan,
    )

    # Rate limiting
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @application.middleware("http")
    async def extract_login_email(request: Request, call_next):
        """Populate request.state.login_email on POST /login for email-keyed rate limiting."""
        if request.method == "POST" and request.url.path == "/login":
            try:
                body = await request.body()
                if body:
                    data = json.loads(body)
                    if isinstance(data, dict) and isinstance(data.get("email"), str):
                        request.state.login_email = data["email"].strip().lower()
            except Exception:
                pass
        return await call_next(request)

    # Routers
    application.include_router(auth.router)
    application.include_router(apps.router)

    # System / discovery endpoints
    @application.get("/health", response_model=MessageResponse, tags=["System"])
    def health_check():
        return {"msg": "Healthy and connection is good"}

    @application.get("/.well-known/jwks.json", tags=["System"])
    def get_jwks():
        return build_jwks()

    return application


app = create_app()
