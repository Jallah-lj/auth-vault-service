from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, vault
from app.config import get_settings
from app.db.database import Base, engine
import app.db.models  # noqa: F401 -- register SQLAlchemy models before create_all

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Suitable for the starter deployment. Use managed migrations before multi-instance production deploys.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Authenticated encrypted credential-vault API.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(auth.router, prefix="/api/v1")
app.include_router(vault.router, prefix="/api/v1")
