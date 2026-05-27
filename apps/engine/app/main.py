from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import auth, domains, health


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Nothing to pre-warm in Phase 0; scanning connection pools go here later.
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Recon Platform — Engine",
        version="0.1.0",
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router,   prefix="/api/v1")
    app.include_router(domains.router, prefix="/api/v1")

    return app


app = create_app()
