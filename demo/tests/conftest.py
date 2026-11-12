"""Configuración de las pruebas de la demo. Correr desde la raíz del repositorio:  python -m pytest demo/tests

Necesitan `cryptography` (la misma que usa demo/init.py) y PyYAML; el resto es la biblioteca estándar. No usan Docker ni el motor:
el motor se reemplaza por uno de mentira (fake_engine.py) que contesta lo mismo que la API real.
"""
import datetime as dt
import http.client
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

DEMO_DIR = Path(__file__).resolve().parent.parent
if str(DEMO_DIR) not in sys.path:
    sys.path.insert(0, str(DEMO_DIR))
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from common import OFF_FLAG, TOKEN_FILE  # noqa: E402
from console import server  # noqa: E402
from fake_engine import FakeEngine  # noqa: E402


@pytest.fixture(scope="session")
def state_dir(tmp_path_factory) -> Path:
    """Credenciales y certificados de práctica generados una vez para todas las pruebas."""
    import init

    directory = tmp_path_factory.mktemp("state")
    original = init.STATE_DIR
    init.STATE_DIR = directory
    try:
        init.ensure_secrets()
        init.ensure_pki(dt.datetime.now(dt.timezone.utc))
    finally:
        init.STATE_DIR = original
    return directory


@pytest.fixture()
def shared_dir(tmp_path) -> Path:
    directory = tmp_path / "shared"
    directory.mkdir()
    return directory


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Console:
    """Una consola arrancada de verdad, más lo necesario para hablarle como lo haría un navegador."""

    def __init__(self, engine: FakeEngine, config: server.Config, demo: server.Demo, http_server) -> None:
        self.engine, self.config, self.demo, self.http_server = engine, config, demo, http_server
        self.port = config.public_port

    def request(self, method: str, path: str, body=None, *, host=None, origin="same", headers=None, raw_body=None):
        """Devuelve (estado, cabeceras, cuerpo en bytes). `origin="same"` manda el Origin de la propia consola, como un navegador."""
        send = {"Host": host or f"localhost:{self.port}"}
        if method == "POST":
            if origin == "same":
                send["Origin"] = f"http://localhost:{self.port}"
            elif origin:
                send["Origin"] = origin
        payload = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        if payload is not None:
            send["Content-Type"] = "application/json"
        send.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=payload, headers=send)
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            connection.close()

    def get(self, path, **kw):
        status, headers, body = self.request("GET", path, **kw)
        return status, (json.loads(body) if body and "json" in headers.get("content-type", "") else body)

    def post(self, path, body=None, **kw):
        status, headers, raw = self.request("POST", path, {} if body is None else body, **kw)
        return status, (json.loads(raw) if raw else None)

    # -- atajos del recorrido ------------------------------------------------------------------------------------------
    def step_account(self):
        assert self.post("/api/account", {"accept_terms": True})[0] == 200

    def step_domain(self):
        assert self.post("/api/domain")[0] == 200

    def step_publish(self):
        assert self.post("/api/file", {"publish": True})[0] == 200

    def step_verify(self):
        status, body = self.post("/api/verify")
        assert status == 200
        return body

    def verified(self):
        self.step_account()
        self.step_domain()
        self.step_publish()
        assert self.step_verify() == {"verified": True}

    def state(self):
        status, body = self.get("/api/state")
        assert status == 200
        return body

    def scan_until_done(self, port_range="top-1000"):
        status, started = self.post("/api/scan", {"port_range": port_range})
        assert status == 200, started
        for _ in range(5):
            status, view = self.get(f"/api/scan/{started['job_id']}")
            assert status == 200
            if view["job"]["status"] == "completed":
                return started["job_id"], view
        raise AssertionError("el escaneo nunca terminó")


@pytest.fixture()
def console(state_dir, shared_dir):
    engine = FakeEngine(shared_dir, OFF_FLAG, TOKEN_FILE)
    url = engine.start()
    port = free_port()
    config = server.Config(
        engine_url=url, public_port=port, state_dir=state_dir, shared_dir=shared_dir,
        listen_host="127.0.0.1", listen_port=port,
    )
    demo = server.Demo(config, server.Engine(config))
    http_server = server.create_server(config, demo)
    threading.Thread(target=lambda: http_server.serve_forever(poll_interval=0.02), daemon=True).start()
    try:
        yield Console(engine, config, demo, http_server)
    finally:
        http_server.shutdown()
        http_server.server_close()
        engine.stop()
