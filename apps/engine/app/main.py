import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import auth, domains, health, scans
from app.security import BodyLimitMiddleware, SecurityHeadersMiddleware, security_headers
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
        # La documentación de la API (y el esquema con todas las rutas) solo en desarrollo.
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # Starlette pone el último middleware agregado como el más externo. CORS va afuera de todo: contesta las
    # consultas previas y agrega sus encabezados también a las respuestas de error (si no, el navegador mostraría
    # un error de CORS en lugar del 413 o el 429 reales). El tope de cuerpo va adentro de todo, así su respuesta
    # también lleva las cabeceras de seguridad.
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.MAX_REQUEST_BYTES)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        # La sesión viaja en el encabezado Authorization, no en cookies: no hace falta permitir credenciales.
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],  # para que la web pueda decir cuánto esperar tras un 429
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        # La respuesta por defecto de FastAPI repite el valor recibido ("input"): en un login o un registro eso es
        # la contraseña, y un error de validación puede quedar en registros de proxies y herramientas del navegador.
        errors = [{"type": e.get("type"), "loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        # Esta respuesta la arma el middleware más externo de Starlette, así que no pasa por los nuestros.
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
            headers=security_headers(),
        )

    app.include_router(health.router,  prefix="/api/v1")
    app.include_router(auth.router,    prefix="/api/v1")
    app.include_router(domains.router, prefix="/api/v1")
    app.include_router(scans.router,   prefix="/api/v1")

    return app


app = create_app()
