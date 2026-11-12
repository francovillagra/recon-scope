"""Consola guiada de la demo de Recon Scope.

Una página que recorre el producto paso a paso, en lenguaje de cliente: crear la cuenta, registrar un dominio, demostrar que es
propio (el motor pide un archivo por HTTPS), escanearlo desde afuera, leer lo que se encontró, corregir y comparar. Cada botón
llama a la API del motor (la misma que usa el panel) y muestra qué contestó.

Usa solo la biblioteca estándar: no hay nada que instalar y el código entero se lee en un rato. Corre dentro de la demo
(docker compose), en una red sin salida a internet; solo la consola se publica, y solo en 127.0.0.1 de la computadora. Aun así
rechaza pedidos de otros sitios web abiertos en el mismo navegador (ver `_host_allowed` y el chequeo de Origin en `do_POST`).
Ver demo/README.md.
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from common import DEFAULT_SHARED_DIR, DEFAULT_STATE_DIR, DOMAIN, OFF_FLAG, TOKEN_FILE, VERIFICATION_PATH

try:  # importado como paquete (las pruebas)
    from . import explain
except ImportError:  # corriendo como script dentro del contenedor
    import explain

log = logging.getLogger("consola")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_EVENTS = 60
MAX_ENGINE_BYTES = 8 * 1024 * 1024
RELOGIN_MIN_SECONDS = 60          # el motor bloquea las cuentas con muchos ingresos fallidos: no insistir
PORT_RANGES = ("top-100", "top-1000")   # "full" (65535 puertos) no tiene sentido en una demo
SCAN_TIMEOUT_SECONDS = 5          # tiempo máximo por conexión; los sitios de práctica contestan al instante
UUID_RE = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
TOKEN_RE = re.compile(r"recon-verify-[0-9a-fA-F-]{36}")

# El motor está en la red interna de la demo: a él nunca se llega por un proxy. Docker Desktop, si la computadora usa uno, lo
# agrega a los contenedores como variable de entorno; con este cliente esa variable se ignora.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

TERMS = (
    "Esta es una demo local. La cuenta de práctica y todo lo que se haga con ella existen solo mientras la demo está encendida: "
    "al apagarla se borran. Los únicos objetivos posibles son los sitios de práctica que la acompañan, y el motor no tiene salida "
    "a internet. Aceptar crea la cuenta de práctica en el motor local."
)

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


@dataclass(frozen=True)
class Config:
    engine_url: str = "http://engine:8000"
    public_port: int = 4100           # el puerto con el que el navegador abre la consola (el publicado por docker)
    state_dir: Path = Path(DEFAULT_STATE_DIR)
    shared_dir: Path = Path(DEFAULT_SHARED_DIR)
    email: str = "demo@example.com"   # solo identifica la cuenta de práctica; nunca se envía un correo
    domain: str = DOMAIN
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get
        return cls(
            engine_url=env("DEMO_ENGINE_URL", cls.engine_url).rstrip("/"),
            public_port=int(env("DEMO_CONSOLE_PUBLIC_PORT", str(cls.public_port))),
            state_dir=Path(env("DEMO_STATE_DIR", str(cls.state_dir))),
            shared_dir=Path(env("DEMO_SHARED_DIR", str(cls.shared_dir))),
            email=env("DEMO_EMAIL", cls.email),
            domain=env("DEMO_DOMAIN", cls.domain),
            listen_host=env("DEMO_LISTEN_HOST", cls.listen_host),
            listen_port=int(env("DEMO_LISTEN_PORT", str(cls.listen_port))),
        )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset({f"localhost:{self.public_port}", f"127.0.0.1:{self.public_port}"})

    @property
    def allowed_origins(self) -> frozenset[str]:
        return frozenset(f"http://{host}" for host in self.allowed_hosts)


def read_secret(directory: Path, name: str) -> str:
    try:
        return (directory / name).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


class Refused(Exception):
    """Algo que se le dice a quien usa la consola, con el código HTTP que corresponde. El mensaje no lleva claves ni detalles internos."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# -- el motor -------------------------------------------------------------------------------------------------------------

class EngineUnavailable(Exception):
    """No hubo respuesta del motor (apagado, arrancando o sin red)."""


class Engine:
    """Cliente mínimo de la API del motor. Guarda el token de la cuenta de práctica solo en memoria."""

    PREFIX = "/api/v1"

    def __init__(self, config: Config, clock: Callable[[], float] = time.monotonic) -> None:
        self._config = config
        self._clock = clock
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._absent = False           # el motor dijo que la cuenta no existe: no insistir hasta crearla
        self._last_login = -RELOGIN_MIN_SECONDS

    # -- sesión ---------------------------------------------------------------------------------------------------------
    @property
    def has_session(self) -> bool:
        return self._token is not None

    def set_token(self, token: Optional[str]) -> None:
        with self._lock:
            self._token = token
            self._absent = token is None and self._absent

    def forget_account(self) -> None:
        with self._lock:
            self._token, self._absent = None, True

    def login(self) -> bool:
        """Entra con la cuenta de práctica. False si el motor no la conoce (todavía no se creó, o la base se reinició)."""
        password = read_secret(self._config.state_dir, "demo_password")
        if not password:
            return False
        status, body = self._once("POST", "/auth/login", {"email": self._config.email, "password": password}, token=None)
        if status == 200 and isinstance(body, dict) and isinstance(body.get("token"), str):
            with self._lock:
                self._token, self._absent = body["token"], False
            return True
        if status == 401:
            self.forget_account()
        return False

    def _relogin(self) -> bool:
        with self._lock:
            if self._absent or self._clock() - self._last_login < RELOGIN_MIN_SECONDS:
                return False
            self._last_login = self._clock()
        return self.login()

    # -- pedidos --------------------------------------------------------------------------------------------------------
    def _once(self, method: str, path: str, body: Any = None, *, token: Optional[str], timeout: float = 25.0) -> tuple[int, Any]:
        status, raw, _ = self._raw(method, path, body, token=token, timeout=timeout)
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    def _raw(
        self, method: str, path: str, body: Any = None, *, token: Optional[str], timeout: float = 25.0
    ) -> tuple[int, bytes, dict]:
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"{self._config.engine_url}{self.PREFIX}{path}", data=data, method=method, headers=headers)
        try:
            with _OPENER.open(request, timeout=timeout) as response:
                return response.status, response.read(MAX_ENGINE_BYTES), dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(MAX_ENGINE_BYTES), dict(exc.headers)
        except (OSError, ValueError) as exc:   # URLError, tiempo agotado, conexión cortada
            raise EngineUnavailable(str(exc)) from None

    def call(self, method: str, path: str, body: Any = None, *, auth: bool = True) -> tuple[int, Any]:
        status, payload = self._once(method, path, body, token=self._token if auth else None)
        if auth and status == 401 and self._relogin():   # el token venció o la base se reinició
            status, payload = self._once(method, path, body, token=self._token)
        if auth and status == 401:
            self.forget_account()
        return status, payload

    def download(self, path: str) -> tuple[int, bytes]:
        status, raw, _ = self._raw("GET", path, token=self._token)
        if status == 401 and self._relogin():
            status, raw, _ = self._raw("GET", path, token=self._token)
        if status == 401:
            self.forget_account()
        return status, raw

    def healthy(self) -> bool:
        try:
            status, _ = self._once("GET", "/health", token=None, timeout=1.5)
            return status == 200
        except EngineUnavailable:
            return False


def engine_message(payload: Any) -> str:
    """El texto 'detail' con que el motor explica un rechazo (en inglés), acotado."""
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, str):
        return detail[:300]
    if isinstance(detail, list) and detail and isinstance(detail[0], dict):
        return str(detail[0].get("msg", ""))[:300]
    return ""


# -- la demo --------------------------------------------------------------------------------------------------------------

class Demo:
    """Los pasos del recorrido. Cada método hace una cosa en el motor o en los sitios de práctica y deja constancia en la lista
    de 'Lo que va pasando'."""

    def __init__(self, config: Config, engine: Engine, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.config = config
        self.engine = engine
        self._clock = clock
        self._lock = threading.Lock()
        self._events: list[dict] = []
        self._seq = 0
        self._reported: set[str] = set()   # escaneos cuyo final ya se anotó

    # -- lista de acontecimientos -------------------------------------------------------------------------------------
    def event(self, text: str, *, ok: bool = True, detail: str = "") -> None:
        with self._lock:
            self._seq += 1
            self._events.append({
                "n": self._seq, "t": self._clock().isoformat(timespec="seconds"), "text": text, "ok": ok, "detail": detail[:400],
            })
            del self._events[:-MAX_EVENTS]

    def events(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def _first_report(self, job_id: str) -> bool:
        """True solo la primera vez que se pregunta por ese escaneo: el final de cada uno se anota una sola vez."""
        with self._lock:
            if job_id in self._reported:
                return False
            self._reported.add(job_id)
            return True

    # -- arranque -----------------------------------------------------------------------------------------------------
    def bootstrap(self, attempts: int = 30, pause: float = 2.0) -> None:
        """Si la cuenta de práctica ya existe en el motor (se reinició solo la consola), entra con ella."""
        for _ in range(attempts):
            if self.engine.healthy():
                self.engine.login()
                return
            time.sleep(pause)

    # -- paso 1: la cuenta --------------------------------------------------------------------------------------------
    def create_account(self, accept_terms: bool) -> None:
        if accept_terms is not True:
            raise Refused(400, "Para crear la cuenta hay que aceptar los términos de la demo.")
        password = read_secret(self.config.state_dir, "demo_password")
        if not password:
            raise Refused(503, "Las credenciales de la demo todavía no están listas. Esperar unos segundos y probar de nuevo.")
        status, body = self.engine.call(
            "POST", "/auth/register", {"email": self.config.email, "password": password, "tos_accepted": True}, auth=False
        )
        if status == 201 and isinstance(body, dict) and isinstance(body.get("token"), str):
            self.engine.set_token(body["token"])
            self.event("Cuenta de práctica creada en el motor local (términos de la demo aceptados).")
            return
        if status == 409 and self.engine.login():   # la cuenta ya estaba (se reinició solo la consola)
            self.event("La cuenta de práctica ya existía: se volvió a entrar con ella.")
            return
        raise Refused(502, f"El motor no pudo crear la cuenta (respondió {status}). {engine_message(body)}".strip())

    # -- paso 2: el dominio -------------------------------------------------------------------------------------------
    def _domain(self) -> Optional[dict]:
        status, body = self.engine.call("GET", "/domains")
        if status != 200 or not isinstance(body, dict):
            return None
        for item in body.get("domains", []):
            if item.get("domain") == self.config.domain:
                return item
        return None

    @staticmethod
    def _account_lost() -> Refused:
        """El motor ya no reconoce la cuenta de práctica (por ejemplo, se reinició la base): hay que crearla de nuevo."""
        return Refused(409, "La cuenta de práctica ya no existe en el motor (se reinició). Crearla de nuevo.")

    def _require_domain(self) -> dict:
        if not self.engine.has_session:
            raise Refused(409, "Primero hay que crear la cuenta de práctica.")
        domain = self._domain()
        if not self.engine.has_session:
            raise self._account_lost()
        if domain is None:
            raise Refused(409, "Primero hay que registrar el dominio.")
        return domain

    def register_domain(self) -> None:
        if not self.engine.has_session:
            raise Refused(409, "Primero hay que crear la cuenta de práctica.")
        status, body = self.engine.call("POST", "/domains", {"domain": self.config.domain})
        if status == 401:
            raise self._account_lost()
        if status == 201:
            self.event(
                f"Dominio registrado: {self.config.domain}. El motor generó un código de verificación; todavía no permite escanear.",
            )
        elif status != 409:   # 409: ya estaba registrado
            raise Refused(502, f"El motor no pudo registrar el dominio (respondió {status}). {engine_message(body)}".strip())

    # -- paso 3: demostrar que el dominio es propio -------------------------------------------------------------------
    def _token_path(self) -> Path:
        return self.config.shared_dir / TOKEN_FILE

    def publish_file(self, publish: bool) -> None:
        domain = self._require_domain()
        path = self._token_path()
        if not publish:
            path.unlink(missing_ok=True)
            self.event("Archivo de verificación retirado del sitio de práctica.")
            return
        token = str(domain.get("verification_token", ""))
        if not TOKEN_RE.fullmatch(token):
            raise Refused(502, "El motor devolvió un código de verificación con un formato inesperado.")
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(token, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        self.event(
            f"Archivo publicado en el sitio de práctica: https://{self.config.domain}{VERIFICATION_PATH}",
            detail="Es lo que el producto le pide a un cliente real: un archivo de texto con el código, en su propio sitio.",
        )

    def verify(self) -> dict:
        domain = self._require_domain()
        status, body = self.engine.call("POST", f"/domains/{domain['id']}/verify", {"method": "well_known_file"})
        if status == 401:
            raise self._account_lost()
        if status == 429:
            raise Refused(429, "El motor limita los intentos de verificación. Esperar unos minutos.")
        if status != 200 or not isinstance(body, dict):
            raise Refused(502, f"El motor no pudo verificar (respondió {status}). {engine_message(body)}".strip())
        verified = (body.get("domain") or {}).get("verification_status") == "verified"
        if verified:
            self.event(
                "Propiedad demostrada: el motor pidió el archivo por HTTPS, comprobó el certificado del sitio y el contenido "
                "coincide con el código.",
            )
        else:
            self.event(
                "El motor no pudo confirmar la propiedad: no encontró el archivo con el código.",
                ok=False, detail=str(body.get("error") or "")[:300],
            )
        return {"verified": verified}

    def try_unverified_scan(self) -> dict:
        """Muestra que el motor se niega a escanear un dominio sin verificar. Solo se permite antes de verificar."""
        domain = self._require_domain()
        if domain.get("verification_status") == "verified":
            raise Refused(409, "El dominio ya está verificado: esta prueba solo tiene sentido antes de verificarlo.")
        status, body = self.engine.call("POST", "/scans", self._scan_request(domain["id"], "top-100"))
        if status == 401:
            raise self._account_lost()
        if status == 422:
            message = engine_message(body)
            self.event(
                "Intento de escanear sin verificar: el motor lo rechazó. Solo escanea dominios cuya propiedad está demostrada.",
                ok=False, detail=message,
            )
            return {"refused": True, "message": message}
        raise Refused(502, f"Respuesta inesperada del motor ({status}).")

    # -- paso 4: escanear ---------------------------------------------------------------------------------------------
    @staticmethod
    def _scan_request(domain_id: str, port_range: str) -> dict:
        return {
            "domain_id": domain_id,
            "modules": ["subdomains", "ports", "fingerprint"],
            "port_range": port_range,
            "timeout_seconds": SCAN_TIMEOUT_SECONDS,
        }

    def start_scan(self, port_range: str) -> dict:
        if port_range not in PORT_RANGES:
            raise Refused(400, "Rango de puertos no permitido en la demo.")
        domain = self._require_domain()
        status, body = self.engine.call("POST", "/scans", self._scan_request(domain["id"], port_range))
        if status == 401:
            raise self._account_lost()
        if status == 201 and isinstance(body, dict):
            self.event(
                f"Escaneo iniciado sobre {self.config.domain}: subdominios, puertos ({port_range}) y huella web.",
                detail="Solo se toca lo que está en el alcance del dominio verificado.",
            )
            return {"job_id": body.get("job_id")}
        if status == 422:
            raise Refused(409, "El dominio todavía no está verificado. Completar el paso anterior.")
        if status == 429:
            raise Refused(429, "El motor limita la cantidad de escaneos (por hora y simultáneos). Esperar unos minutos.")
        raise Refused(502, f"El motor no pudo iniciar el escaneo (respondió {status}). {engine_message(body)}".strip())

    # -- paso 5: resultados -------------------------------------------------------------------------------------------
    def scan_view(self, job_id: str) -> dict:
        if not self.engine.has_session:
            raise Refused(409, "Primero hay que crear la cuenta de práctica.")
        status, body = self.engine.call("GET", f"/scans/{job_id}")
        if status == 401:
            raise self._account_lost()
        if status == 404:
            raise Refused(404, "No existe ese escaneo.")
        if status != 200 or not isinstance(body, dict):
            raise Refused(502, f"El motor no pudo dar el escaneo (respondió {status}).")
        job = body.get("job") or {}
        view: dict[str, Any] = {
            "job": {
                key: job.get(key)
                for key in ("id", "status", "progress", "error_message", "created_at", "started_at", "completed_at", "config")
            },
        }
        if job.get("status") != "completed":
            if job.get("status") == "failed" and self._first_report(job_id):
                self.event("El escaneo falló.", ok=False, detail=str(job.get("error_message") or ""))
            return view

        subdomains = body.get("subdomains", [])
        host_names = {s["resolved_ip"]: s["hostname"] for s in subdomains if s.get("resolved_ip")}
        findings = [explain.explain(f, host_names) for f in body.get("findings", [])]
        counts = explain.count_by_severity(findings)
        view.update({
            "counts": counts,
            "summary": explain.summary_line(counts),
            "findings": findings,
            "subdomains": [{"hostname": s.get("hostname"), "ip": s.get("resolved_ip")} for s in subdomains],
            "ports": [
                {
                    "host": p.get("host"), "name": host_names.get(str(p.get("host")), ""), "port": p.get("port"),
                    "service": p.get("service"), "banner": explain.readable_banner(p.get("banner")),
                }
                for p in body.get("ports", [])
            ],
            "web": [
                {"url": f.get("url"), "status": f.get("status_code"), "server": f.get("server_header"), "title": f.get("title")}
                for f in body.get("http_fingerprints", [])
            ],
            "technologies": [
                {"name": t.get("name"), "version": t.get("version"), "category": t.get("category")}
                for t in body.get("technologies", [])
            ],
            "tls": [
                {
                    "host": c.get("host"), "issuer": c.get("issuer"), "valid": c.get("is_valid"),
                    "valid_to": c.get("valid_to"), "san": c.get("san"),
                }
                for c in body.get("tls_certificates", [])
            ],
        })
        if self._first_report(job_id):
            total = len(findings)
            self.event(f"Escaneo terminado: {total} {'hallazgo' if total == 1 else 'hallazgos'} ({view['summary']}).")
        return view

    def report(self, job_id: str) -> tuple[bytes, str]:
        if not self.engine.has_session:
            raise Refused(409, "Primero hay que crear la cuenta de práctica.")
        status, raw = self.engine.download(f"/scans/{job_id}/export/json")
        if status == 401:
            raise self._account_lost()
        if status != 200:
            raise Refused(404 if status == 404 else 502, "No se pudo obtener el informe.")
        return raw, f"recon-scope-demo-{self._clock().date().isoformat()}.json"

    # -- paso 6: corregir y comparar ----------------------------------------------------------------------------------
    def _off_flag(self) -> Path:
        return self.config.shared_dir / OFF_FLAG

    def staging_on(self) -> bool:
        return not self._off_flag().exists()

    def set_staging(self, on: bool) -> None:
        flag = self._off_flag()
        if on:
            flag.unlink(missing_ok=True)
            self.event("Servidor de pruebas encendido otra vez.")
        else:
            flag.write_text("off\n", encoding="utf-8")
            os.chmod(flag, 0o644)
            self.event(
                "Servidor de pruebas apagado: simula que el cliente lo dio de baja. Volver a escanear para ver qué cambia.",
            )

    def reset(self) -> None:
        if self.engine.has_session:
            domain = self._domain()
            if domain is not None:
                status, _ = self.engine.call("DELETE", f"/domains/{domain['id']}")
                if status not in (200, 204):
                    raise Refused(502, f"El motor no pudo borrar el dominio (respondió {status}).")
        self._token_path().unlink(missing_ok=True)
        self._off_flag().unlink(missing_ok=True)
        with self._lock:
            self._reported.clear()
        self.event("Demo reiniciada: dominio, escaneos y archivos de práctica borrados. La cuenta de práctica se conserva.")

    # -- estado para la página ----------------------------------------------------------------------------------------
    def state(self) -> dict:
        out: dict[str, Any] = {
            "engine_ready": False, "account": False, "domain_name": self.config.domain, "email": self.config.email,
            "terms": TERMS, "domain": None, "file_published": False, "staging_on": self.staging_on(),
            "history": [], "events": self.events(),
        }
        if not self.engine.healthy():
            return out
        out["engine_ready"] = True
        if not self.engine.has_session:
            return out
        try:
            domain = self._domain()
        except EngineUnavailable:
            out["engine_ready"] = False
            return out
        if not self.engine.has_session:   # el motor ya no reconoce la cuenta (la base se reinició)
            return out
        out["account"] = True
        if domain is None:
            return out

        token = str(domain.get("verification_token", ""))
        published = read_secret(self.config.shared_dir, TOKEN_FILE)
        out["file_published"] = bool(token) and published == token
        out["domain"] = {
            "id": domain.get("id"),
            "status": domain.get("verification_status"),
            "token": token,
            "file_url": f"https://{self.config.domain}{VERIFICATION_PATH}",
        }
        status, history = self.engine.call("GET", f"/domains/{domain['id']}/history")
        if status == 200 and isinstance(history, list):
            out["history"] = [
                {
                    "id": h.get("id"), "status": h.get("status"), "created_at": h.get("created_at"),
                    "completed_at": h.get("completed_at"), "port_range": (h.get("config") or {}).get("port_range"),
                    "subdomains": h.get("subdomains_count"), "open_ports": h.get("open_ports_count"),
                    "counts": h.get("findings_by_severity") or {},
                    "summary": explain.summary_line(h.get("findings_by_severity") or {}),
                }
                for h in history
            ]
        return out


# -- HTTP -----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Asset:
    body: bytes
    content_type: str


def load_assets() -> dict[str, Asset]:
    files = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        "/style.css": ("style.css", "text/css; charset=utf-8"),
    }
    return {url: Asset((STATIC_DIR / name).read_bytes(), ctype) for url, (name, ctype) in files.items()}


def create_server(config: Config, demo: Demo) -> ThreadingHTTPServer:
    assets = load_assets()
    scan_path = re.compile(rf"/api/scan/({UUID_RE})")
    report_path = re.compile(rf"/api/report/({UUID_RE})")

    class Handler(BaseHTTPRequestHandler):
        server_version = "consola"
        sys_version = ""

        # -- registro y respuestas ------------------------------------------------------------------------------------
        def log_request(self, code="-", size="-") -> None:
            # La página consulta /api/state todo el tiempo: no llenar el registro con eso.
            if str(code) == "200" and (self.path.split("?")[0] in ("/api/state", "/healthz") or self.path.startswith("/api/scan/")):
                return
            super().log_request(code, size)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            sys.stderr.write("%s\n" % (format % args))

        def send_response(self, code, message=None) -> None:
            # Igual que la clase base, pero sin la cabecera Server: no hace falta anunciar qué es.
            self.log_request(code)
            self.send_response_only(code, message)

        def _send(self, status: int, body: bytes, content_type: str, extra: Optional[dict[str, str]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        # -- protección contra otros sitios abiertos en el mismo navegador ----------------------------------------------
        def _host_allowed(self) -> bool:
            # Un sitio ajeno que apunte su dominio a 127.0.0.1 (DNS rebinding) llega con su propio Host: se rechaza.
            return self.headers.get("Host", "").lower() in config.allowed_hosts

        def _run(self, action: Callable[[], Any]) -> None:
            try:
                self._json(200, action())
            except Refused as exc:
                self._json(exc.status, {"error": exc.message})
            except EngineUnavailable:
                self._json(503, {"error": "No se pudo hablar con el motor. Puede estar todavía arrancando: esperar unos segundos."})
            except Exception:  # noqa: BLE001 - un error propio no puede dejar la consola sin responder
                log.exception("Falló %s", self.path)
                self._json(500, {"error": "La consola tuvo un error inesperado (el detalle está en su registro)."})

        # -- rutas ----------------------------------------------------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path == "/healthz":  # sin chequeo de Host: lo consulta docker desde dentro del contenedor
                return self._send(200, b"ok", "text/plain; charset=utf-8")
            if not self._host_allowed():
                return self._json(421, {"error": "host no permitido"})
            asset = assets.get(path)
            if asset:
                return self._send(200, asset.body, asset.content_type)
            if path == "/api/state":
                return self._run(demo.state)
            match = scan_path.fullmatch(path)
            if match:
                return self._run(lambda: demo.scan_view(match.group(1)))
            match = report_path.fullmatch(path)
            if match:
                try:
                    body, filename = demo.report(match.group(1))
                except Refused as exc:
                    return self._json(exc.status, {"error": exc.message})
                except EngineUnavailable:
                    return self._json(503, {"error": "No se pudo hablar con el motor."})
                return self._send(
                    200, body, "application/json; charset=utf-8", {"Content-Disposition": f'attachment; filename="{filename}"'}
                )
            self._json(404, {"error": "no existe"})

        def _body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise Refused(400, "pedido inválido") from None
            if length > 1024:
                raise Refused(413, "pedido demasiado grande")
            if not length:
                return {}
            try:
                data = json.loads(self.rfile.read(length))
            except ValueError:
                raise Refused(400, "pedido inválido") from None
            return data if isinstance(data, dict) else {}

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_allowed():
                return self._json(421, {"error": "host no permitido"})
            # Los navegadores mandan siempre Origin en un POST. Si no es el de esta consola, lo mandó otra página.
            if self.headers.get("Origin") not in config.allowed_origins:
                return self._json(403, {"error": "origen no permitido"})
            path = urlsplit(self.path).path

            def action() -> Any:
                body = self._body()
                if path == "/api/account":
                    demo.create_account(body.get("accept_terms") is True)
                elif path == "/api/domain":
                    demo.register_domain()
                elif path == "/api/file":
                    demo.publish_file(body.get("publish", True) is not False)
                elif path == "/api/verify":
                    return demo.verify()
                elif path == "/api/try-scan":
                    return demo.try_unverified_scan()
                elif path == "/api/scan":
                    return demo.start_scan(str(body.get("port_range", "top-1000")))
                elif path == "/api/staging":
                    demo.set_staging(body.get("on") is True)
                elif path == "/api/reset":
                    demo.reset()
                else:
                    raise Refused(404, "no existe")
                return {"ok": True}

            self._run(action)

    return ThreadingHTTPServer((config.listen_host, config.listen_port), Handler)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = Config.from_env()
    demo = Demo(config, Engine(config))
    server = create_server(config, demo)
    threading.Thread(target=demo.bootstrap, daemon=True).start()
    # docker stop manda SIGTERM; como proceso 1 el intérprete lo ignoraría y la parada tardaría diez segundos.
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    print(f"Consola de la demo lista: http://localhost:{config.public_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
