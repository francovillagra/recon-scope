"""La consola: pedidos HTTP reales contra el servidor de la consola, con un motor de mentira (fake_engine.py) en lugar del verdadero."""
from __future__ import annotations

import json
import re
import stat
from datetime import datetime, timezone

import pytest

from common import DOMAIN, OFF_FLAG, TOKEN_FILE
from console import explain, server

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


# -- protecciones del servidor -----------------------------------------------------------------------------------------------

def test_the_page_and_its_files_are_served(console):
    for path, kind in (("/", "text/html"), ("/app.js", "text/javascript"), ("/style.css", "text/css")):
        status, headers, body = console.request("GET", path)
        assert status == 200 and headers["content-type"].startswith(kind) and body
    page = console.request("GET", "/")[2]
    assert b'<script src="/app.js" defer></script>' in page
    assert not re.search(rb"<script(?![^>]*\ssrc=)", page) and b" onclick=" not in page   # sin código dentro de la página: la política lo exige


def test_security_headers_and_no_server_banner(console):
    status, headers, _ = console.request("GET", "/")
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"
    assert "server" not in headers   # no anuncia qué programa es


def test_other_hosts_are_refused_but_healthz_is_open_to_docker(console):
    for path in ("/", "/api/state", "/app.js"):
        assert console.request("GET", path, host="sitio-ajeno.example")[0] == 421
        assert console.request("GET", path, host=f"localhost:{console.port + 1}")[0] == 421
    assert console.request("POST", "/api/reset", {}, host="sitio-ajeno.example")[0] == 421
    status, _, body = console.request("GET", "/healthz", host="engine:8080")   # el chequeo de docker llega con otro Host
    assert (status, body) == (200, b"ok")


def test_both_local_names_are_accepted(console):
    assert console.request("GET", "/api/state", host=f"127.0.0.1:{console.port}")[0] == 200
    assert console.request("GET", "/api/state", host=f"LOCALHOST:{console.port}")[0] == 200


def test_posts_need_the_origin_of_the_console(console):
    assert console.request("POST", "/api/reset", {}, origin=None)[0] == 403
    assert console.request("POST", "/api/reset", {}, origin="https://sitio-ajeno.example")[0] == 403
    assert console.request("POST", "/api/reset", {}, origin="null")[0] == 403
    assert console.request("POST", "/api/reset", {}, origin=f"http://127.0.0.1:{console.port}")[0] == 200
    assert console.engine.requests == []   # los rechazados no llegaron ni a tocar el motor


def test_bad_requests_get_clear_errors(console):
    assert console.request("POST", "/api/account", raw_body=b"x" * 2000)[0] == 413
    assert console.request("POST", "/api/account", raw_body=b"{no es json")[0] == 400
    assert console.request("POST", "/api/account", headers={"Content-Length": "abc"})[0] == 400
    assert console.request("POST", "/api/no-existe", {})[0] == 404
    assert console.request("GET", "/api/no-existe")[0] == 404
    assert console.request("GET", "/api/scan/no-es-un-uuid")[0] == 404
    assert console.request("GET", "/api/report/../../etc/passwd")[0] == 404


def test_errors_never_leak_internals(console, monkeypatch):
    def boom():
        raise RuntimeError("ruta secreta /run/demo/jwt_secret")

    monkeypatch.setattr(console.demo, "state", boom)
    status, body = console.get("/api/state")
    assert status == 500 and "secreta" not in json.dumps(body) and "jwt_secret" not in json.dumps(body)


def test_engine_down_gives_a_clear_message(console):
    console.engine.stop()
    status, body = console.post("/api/account", {"accept_terms": True})
    assert status == 503 and "motor" in body["error"]
    assert console.state()["engine_ready"] is False


# -- el recorrido -------------------------------------------------------------------------------------------------------------

def test_initial_state(console):
    state = console.state()
    assert state["engine_ready"] is True and state["account"] is False and state["domain"] is None
    assert state["domain_name"] == DOMAIN and state["staging_on"] is True and state["file_published"] is False
    assert state["terms"] and "demo" in state["terms"].lower()


def test_account_is_created_only_after_accepting_the_terms(console):
    for body in ({}, {"accept_terms": False}, {"accept_terms": "true"}, {"accept_terms": 1}):
        status, answer = console.post("/api/account", body)
        assert status == 400 and "términos" in answer["error"]
    assert console.engine.registrations == 0 and console.engine.requests == []

    assert console.post("/api/account", {"accept_terms": True})[0] == 200
    (method, path, payload, token), = [r for r in console.engine.requests if r[1].endswith("/auth/register")]
    assert payload["tos_accepted"] is True and payload["email"] == "demo@example.com"
    assert payload["password"] == (console.config.state_dir / "demo_password").read_text().strip()
    assert console.state()["account"] is True


def test_account_can_be_created_again_after_a_console_restart(console):
    console.step_account()
    console.demo.engine.forget_account()   # se reinició solo la consola: el motor todavía conoce la cuenta
    assert console.state()["account"] is False
    assert console.post("/api/account", {"accept_terms": True})[0] == 200   # 409 del motor -> vuelve a entrar con la misma cuenta
    assert console.engine.logins == 1 and console.state()["account"] is True


def test_the_demo_password_is_never_sent_to_the_page(console):
    password = (console.config.state_dir / "demo_password").read_text().strip()
    console.verified()
    job_id, _ = console.scan_until_done()
    everything = json.dumps([console.state(), console.get(f"/api/scan/{job_id}")[1]])
    assert password not in everything
    assert "token-" not in everything   # tampoco el token de sesión del motor


def test_steps_are_refused_in_the_wrong_order(console):
    for path in ("/api/domain", "/api/file", "/api/verify", "/api/try-scan", "/api/scan"):
        status, body = console.post(path, {})
        assert status == 409, (path, body)
    console.step_account()
    for path in ("/api/file", "/api/verify", "/api/try-scan", "/api/scan"):
        assert console.post(path, {})[0] == 409, path   # falta registrar el dominio


def test_domain_is_registered_once_and_stays_pending(console):
    console.step_account()
    console.step_domain()
    console.step_domain()   # el segundo registro no rompe nada
    domain = console.state()["domain"]
    assert domain["status"] == "pending" and re.fullmatch(r"recon-verify-[0-9a-f-]{36}", domain["token"])
    assert domain["file_url"] == f"https://{DOMAIN}/.well-known/recon-verification.txt"
    assert len(console.engine.domains) == 1


def test_verification_file_holds_exactly_the_token(console):
    console.step_account()
    console.step_domain()
    token = console.state()["domain"]["token"]
    assert console.state()["file_published"] is False

    console.step_publish()
    path = console.config.shared_dir / TOKEN_FILE
    assert path.read_text(encoding="utf-8") == token   # el motor compara body.strip() == token: ni un carácter de más
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert not list(console.config.shared_dir.glob("*.tmp"))
    assert console.state()["file_published"] is True

    assert console.post("/api/file", {"publish": False})[0] == 200
    assert not path.exists() and console.state()["file_published"] is False


def test_verification_fails_without_the_file_and_works_with_it(console):
    console.step_account()
    console.step_domain()
    assert console.step_verify() == {"verified": False}
    assert console.state()["domain"]["status"] == "failed"
    assert console.demo.events()[-1]["ok"] is False

    console.step_publish()
    assert console.step_verify() == {"verified": True}
    assert console.state()["domain"]["status"] == "verified"
    verify_calls = [r for r in console.engine.requests if r[1].endswith("/verify")]
    assert [r[2] for r in verify_calls] == [{"method": "well_known_file"}] * 2   # siempre por archivo HTTPS, nunca por DNS


def test_a_wrong_file_does_not_verify(console):
    console.step_account()
    console.step_domain()
    (console.config.shared_dir / TOKEN_FILE).write_text("recon-verify-" + "0" * 8 + "-0000-0000-0000-" + "0" * 12)
    assert console.step_verify() == {"verified": False}


def test_scanning_without_verification_is_refused_by_the_engine(console):
    console.step_account()
    console.step_domain()
    status, body = console.post("/api/try-scan")
    assert status == 200 and body["refused"] is True and "not verified" in body["message"]
    assert console.post("/api/scan", {"port_range": "top-100"})[0] == 409
    assert not console.engine.scans   # el motor nunca creó un escaneo

    console.step_publish()
    console.step_verify()
    status, body = console.post("/api/try-scan")
    assert status == 409 and "ya está verificado" in body["error"]   # solo tiene sentido antes de verificar


def test_scan_request_is_bounded(console):
    console.verified()
    for bad in ("full", "top-100; drop table", "", 5):
        status, _ = console.post("/api/scan", {"port_range": bad})
        assert status == 400, bad
    assert not console.engine.scans

    status, started = console.post("/api/scan", {"port_range": "top-100"})
    assert status == 200 and UUID.match(started["job_id"])
    scan = console.engine.scans[started["job_id"]]
    assert scan["config"] == {
        "domain_id": scan["domain_id"], "modules": ["subdomains", "ports", "fingerprint"], "port_range": "top-100", "timeout_seconds": 5,
    }


def test_scan_results_are_explained_for_a_client(console):
    console.verified()
    status, started = console.post("/api/scan", {"port_range": "top-1000"})
    _, running = console.get(f"/api/scan/{started['job_id']}")
    assert running["job"]["status"] == "running" and "findings" not in running

    job_id, view = console.scan_until_done()
    assert view["counts"] == {"critical": 0, "high": 2, "medium": 1, "low": 5, "info": 0}
    assert view["summary"] == "2 altos, 1 medio, 5 bajos"
    titles = [f["title"] for f in view["findings"]]
    assert "Una base de datos está accesible desde la red" in titles
    assert "El certificado de seguridad no es válido" in titles
    database = next(f for f in view["findings"] if f["raw_title"] == "Database port exposed")
    assert database["where"] == "pruebas.tienda-demo.test (172.20.0.5)"      # la dirección se traduce al nombre del subdominio
    assert database["todo"] and database["what"] and database["evidence"]["port"] == 3306  # y conserva el dato técnico original
    assert {p["port"] for p in view["ports"]} == {443, 21, 22, 3306}
    assert [s["hostname"] for s in view["subdomains"]] == ["pruebas.tienda-demo.test"]
    assert {t["name"] for t in view["technologies"]} == {"nginx", "Apache", "PHP"}
    assert next(c for c in view["tls"] if c["host"].startswith("pruebas"))["valid"] is False


def test_the_end_of_each_scan_is_logged_once(console):
    console.verified()
    job_id, _ = console.scan_until_done()
    for _ in range(3):
        console.get(f"/api/scan/{job_id}")
    finished = [e for e in console.demo.events() if e["text"].startswith("Escaneo terminado")]
    assert len(finished) == 1 and "2 altos, 1 medio, 5 bajos" in finished[0]["text"]


def test_turning_the_staging_server_off_changes_the_next_scan(console):
    console.verified()
    _, before = console.scan_until_done()
    assert console.state()["staging_on"] is True

    assert console.post("/api/staging", {"on": False})[0] == 200
    assert (console.config.shared_dir / OFF_FLAG).exists() and console.state()["staging_on"] is False
    _, after = console.scan_until_done()
    assert after["summary"] == "1 bajo" and len(after["ports"]) == 1
    assert len(after["findings"]) < len(before["findings"])
    texts = [e["text"] for e in console.demo.events() if e["text"].startswith("Escaneo terminado")]
    assert texts[-1].startswith("Escaneo terminado: 1 hallazgo (1 bajo)")   # singular cuando es uno solo
    assert texts[0].startswith("Escaneo terminado: 8 hallazgos")

    assert console.post("/api/staging", {"on": True})[0] == 200
    assert not (console.config.shared_dir / OFF_FLAG).exists() and console.state()["staging_on"] is True


def test_history_lists_every_scan_with_its_summary(console):
    console.verified()
    console.scan_until_done("top-100")
    console.post("/api/staging", {"on": False})
    console.scan_until_done("top-1000")
    history = console.state()["history"]
    assert len(history) == 2
    assert {h["port_range"] for h in history} == {"top-100", "top-1000"}
    assert {h["summary"] for h in history} == {"2 altos, 1 medio, 5 bajos", "1 bajo"}


def test_the_report_downloads_as_a_json_file(console):
    console.verified()
    job_id, _ = console.scan_until_done()
    status, headers, body = console.request("GET", f"/api/report/{job_id}")
    today = datetime.now(timezone.utc).date().isoformat()
    assert status == 200 and headers["content-disposition"] == f'attachment; filename="recon-scope-demo-{today}.json"'
    assert json.loads(body)["job"]["id"] == job_id
    assert console.request("GET", "/api/report/00000000-0000-0000-0000-000000000000")[0] == 404


def test_reset_clears_the_domain_and_the_practice_files_but_keeps_the_account(console):
    console.verified()
    console.scan_until_done()
    console.post("/api/staging", {"on": False})
    assert console.post("/api/reset")[0] == 200
    state = console.state()
    assert state["account"] is True and state["domain"] is None and state["staging_on"] is True and state["file_published"] is False
    assert not (console.config.shared_dir / TOKEN_FILE).exists() and not (console.config.shared_dir / OFF_FLAG).exists()
    assert not console.engine.domains and not console.engine.scans
    console.step_domain()   # y el recorrido puede empezar de nuevo desde el paso 2
    console.step_publish()
    assert console.step_verify() == {"verified": True}
    job_id, view = console.scan_until_done()
    assert view["summary"] == "2 altos, 1 medio, 5 bajos"


def test_when_the_engine_loses_the_account_the_console_asks_to_start_over(console):
    console.verified()
    job_id, _ = console.scan_until_done()
    console.engine.reset_database()                    # se reinició la base del motor: no reconoce ni el token ni la cuenta
    status, body = console.get(f"/api/scan/{job_id}")
    assert status == 409 and "Crearla de nuevo" in body["error"]   # la consola no inventa resultados
    assert console.state()["account"] is False and console.state()["domain"] is None
    assert console.request("GET", f"/api/report/{job_id}")[0] == 409
    for path in ("/api/domain", "/api/file", "/api/verify", "/api/scan"):
        assert console.post(path, {})[0] == 409, path
    console.step_account()                             # y crear la cuenta de nuevo alcanza para seguir
    console.step_domain()
    assert console.state()["account"] is True and console.state()["domain"]["status"] == "pending"


# -- el cliente del motor ---------------------------------------------------------------------------------------------------

class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def engine_client(console):
    """Un cliente del motor con reloj propio y la cuenta de práctica ya creada."""
    clock = Clock()
    client = server.Engine(console.config, clock)
    password = (console.config.state_dir / "demo_password").read_text().strip()
    status, body = client.call("POST", "/auth/register", {"email": console.config.email, "password": password, "tos_accepted": True}, auth=False)
    assert status == 201
    client.set_token(body["token"])
    return client, clock, console.engine


def test_engine_client_signs_in_again_when_the_token_is_lost(engine_client):
    client, _, fake = engine_client
    fake.tokens.clear()                                 # el token venció; la cuenta sigue existiendo
    status, body = client.call("GET", "/domains")
    assert status == 200 and body == {"domains": []} and fake.logins == 1 and client.has_session


def test_engine_client_waits_a_minute_between_automatic_logins(engine_client):
    client, clock, fake = engine_client
    fake.tokens.clear()
    assert client.call("GET", "/domains")[0] == 200 and fake.logins == 1   # la primera vez vuelve a entrar sola
    fake.tokens.clear()
    assert client.call("GET", "/domains")[0] == 401 and fake.logins == 1   # dentro del minuto no insiste
    assert not client.has_session


def test_engine_client_does_not_hammer_the_login(engine_client):
    client, _, fake = engine_client
    fake.reset_database()                               # la base se reinició: la cuenta ya no existe
    assert client.call("GET", "/domains")[0] == 401
    assert fake.logins == 1 and not client.has_session
    for _ in range(5):                                  # el motor bloquea las cuentas con ingresos fallidos: no insistir
        client.call("GET", "/domains")
    assert fake.logins == 1


def test_engine_client_ignores_proxy_variables(console, monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")   # un proxy que no existe: si lo usara, fallaría
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    assert server.Engine(console.config).healthy() is True


def test_engine_message_is_short_and_safe():
    assert server.engine_message({"detail": "x" * 1000}) == "x" * 300
    assert server.engine_message({"detail": [{"msg": "campo inválido", "loc": ["body"]}]}) == "campo inválido"
    assert server.engine_message({"detail": {"otra": "cosa"}}) == "" and server.engine_message(None) == ""


# -- los textos ------------------------------------------------------------------------------------------------------------------

def test_every_finding_of_the_engine_has_an_explanation():
    """Para cada regla del motor hay un texto de cliente (y el dato técnico original se conserva)."""
    samples = [
        {"category": "exposed_port", "severity": "high", "title": "Database port exposed", "evidence": {"host": "10.0.0.5", "port": 3306, "service": "mysql"}},
        {"category": "exposed_port", "severity": "medium", "title": "SSH exposed", "evidence": {"host": "10.0.0.5", "port": 22}},
        {"category": "expired_certificate", "severity": "high", "title": "TLS certificate expired", "evidence": {"host": "a.test", "valid_to": "2024-01-02T00:00:00Z"}},
        {"category": "insecure_tls", "severity": "high", "title": "Invalid or expired TLS certificate", "evidence": {"host": "a.test"}},
        {"category": "missing_security_header", "severity": "low", "title": "Missing hsts header", "evidence": {"url": "https://a.test/", "missing_header": "strict-transport-security"}},
        {"category": "missing_security_header", "severity": "low", "title": "Missing otra header", "evidence": {"url": "https://a.test/", "missing_header": "x-otra"}},
        {"category": "information_disclosure", "severity": "low", "title": "Server version disclosure", "evidence": {"url": "https://a.test/", "server_header": "Apache/2.4.29"}},
    ]
    for sample in samples:
        shown = explain.explain(sample, {"10.0.0.5": "pruebas.tienda-demo.test"})
        assert shown["title"] != sample["title"]
        assert shown["what"] and shown["todo"] and shown["where"]
        assert shown["raw_title"] == sample["title"] and shown["evidence"] == sample["evidence"]
    unknown = explain.explain({"category": "otra", "severity": "info", "title": "Nota", "description": "texto del motor"}, {})
    assert unknown["title"] == "Nota" and unknown["what"] == "texto del motor"   # lo que no se conoce se muestra tal cual


def test_service_banners_are_readable():
    assert explain.readable_banner("220 (vsFTPd 3.0.3)") == "220 (vsFTPd 3.0.3)"
    assert explain.readable_banner("SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7") == "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7"
    mysql = "[... 5.7.33-0ubuntu0.18.04.1.....abcdefgh.\ufffd\ufffd!..\ufffd\ufffd...........ijklmnopqrst .mysql_native_password."
    shown = explain.readable_banner(mysql)
    assert "\ufffd" not in shown and "5.7.33-0ubuntu0.18.04.1" in shown and shown.endswith("mysql_native_password.")   # queda lo que importa
    assert explain.readable_banner(None) is None and explain.readable_banner("   ") is None and explain.readable_banner(5) is None
    assert len(explain.readable_banner("a" * 500)) == 100


def test_summary_line_reads_naturally():
    assert explain.summary_line({"high": 2, "medium": 1, "low": 5}) == "2 altos, 1 medio, 5 bajos"
    assert explain.summary_line({"low": 1}) == "1 bajo"
    assert explain.summary_line({}) == "sin hallazgos"
    assert explain.count_by_severity([{"severity": "low"}, {"severity": "low"}, {"severity": "raro"}])["low"] == 2


# -- el README nombra lo que la página realmente tiene ---------------------------------------------------------------------------

def test_the_readme_names_the_buttons_and_texts_the_page_really_has():
    readme = (server.STATIC_DIR.parent.parent / "README.md").read_text(encoding="utf-8")
    page = "".join((server.STATIC_DIR / name).read_text(encoding="utf-8") for name in ("index.html", "app.js"))
    labels = [
        "Crear la cuenta de práctica", "Registrar tienda-demo.test", "Probar un escaneo ahora", "Verificar propiedad",
        "Publicar el archivo en el sitio", "Iniciar escaneo", "Detalle técnico del escaneo", "Descargar el informe completo (JSON)",
        "Apagar el servidor de pruebas", "Escanear de nuevo", "Reiniciar el recorrido", "Lo que va pasando", "Sitios de práctica",
        "Sistema listo", "Crear cuenta", "Registrar el dominio", "Demostrar que el dominio es propio", "Escanear desde afuera",
        "Qué se encontró", "Corregir y comparar",
    ]
    for label in labels:
        assert f"**{label}**" in readme or label in readme, f"el README no menciona «{label}»"
        # el botón del dominio se arma con el nombre del dominio: "Registrar ${domain_name}"
        in_page = "Registrar ${d.domain_name}" in page if label == "Registrar tienda-demo.test" else label in page
        assert in_page, f"la página ya no tiene «{label}», pero el README la nombra"
    assert "Consola de la demo lista" in readme
    assert "Consola de la demo lista" in (server.STATIC_DIR.parent / "server.py").read_text(encoding="utf-8")


def test_the_readme_summaries_match_what_the_translation_produces():
    readme = (server.STATIC_DIR.parent.parent / "README.md").read_text(encoding="utf-8")
    assert f"`{explain.summary_line({'high': 2, 'medium': 1, 'low': 5})}`" in readme       # 2 altos, 1 medio, 5 bajos
    assert f"`{explain.summary_line({'low': 1})}`" in readme                              # 1 bajo
