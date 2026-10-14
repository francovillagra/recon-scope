import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import auth, domains, health, scans
from app.services.scan_runner import recover_stale_jobs

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Los escaneos corren dentro del proceso: si el servidor se reinició a mitad de uno, el trabajo quedó
    # 'running' para siempre. Sin base de datos disponible el motor igual arranca.
    try:
        recovered = await recover_stale_jobs()
        if recovered:
            logger.warning("Marked %d interrupted scan(s) as failed", recovered)
    except Exception:
        logger.warning("Could not check for interrupted scans at startup", exc_info=True)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="recon-scope",
        version="1.0.0",
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

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    app.include_router(health.router,  prefix="/api/v1")
    app.include_router(auth.router,    prefix="/api/v1")
    app.include_router(domains.router, prefix="/api/v1")
    app.include_router(scans.router,   prefix="/api/v1")

    return app


app = create_app()
