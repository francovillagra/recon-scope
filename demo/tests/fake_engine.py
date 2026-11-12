"""Un motor de mentira para probar la consola sin Docker ni base de datos.

Contesta lo mismo que la API real (apps/engine/app/routers) en las rutas que usa la consola: mismos caminos, mismos códigos y
mismos nombres de campos. No escanea nada: devuelve resultados armados a mano, uno para "servidor de pruebas encendido" y otro para
"apagado". La prueba de punta a punta con el motor verdadero está en demo/README.md (sección "Cómo se probó").
"""
from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

STAGING_IP = "172.20.0.5"
NOW = "2026-11-12T12:00:00Z"


def _finding(category, severity, title, description, evidence):
    return {"id": str(uuid.uuid4()), "category": category, "severity": severity, "title": title,
            "description": description, "evidence": evidence, "created_at": NOW}


def result_staging_on() -> dict:
    https = lambda host: f"https://{host}"  # noqa: E731
    return {
        "subdomains": [{"id": "s1", "hostname": "pruebas.tienda-demo.test", "source": "crt_sh", "resolved_ip": STAGING_IP, "created_at": NOW}],
        "ports": [
            {"id": "p1", "host": "tienda-demo.test", "port": 443, "protocol": "tcp", "state": "open", "service": "https", "banner": None, "created_at": NOW},
            {"id": "p2", "host": STAGING_IP, "port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "banner": "220 (vsFTPd 3.0.3)", "created_at": NOW},
            {"id": "p3", "host": STAGING_IP, "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7", "created_at": NOW},
            {"id": "p4", "host": STAGING_IP, "port": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "banner": "5.7.33", "created_at": NOW},
        ],
        "http_fingerprints": [
            {"id": "f1", "url": https("tienda-demo.test/"), "status_code": 200, "server_header": "nginx", "title": "Tienda Demo", "created_at": NOW},
            {"id": "f2", "url": https("pruebas.tienda-demo.test/"), "status_code": 200, "server_header": "Apache/2.4.29 (Ubuntu)",
             "title": "Tienda Demo (pruebas) - Just another WordPress site", "created_at": NOW},
        ],
        "technologies": [
            {"id": "t1", "name": "nginx", "category": "web-server", "version": None, "confidence": 90, "created_at": NOW},
            {"id": "t2", "name": "Apache", "category": "web-server", "version": "2.4.29", "confidence": 90, "created_at": NOW},
            {"id": "t3", "name": "PHP", "category": "language", "version": "7.2.24", "confidence": 90, "created_at": NOW},
        ],
        "tls_certificates": [
            {"id": "c1", "host": "tienda-demo.test", "issuer": "Recon Scope Demo", "subject": "tienda-demo.test", "valid_from": NOW,
             "valid_to": "2027-11-12T12:00:00Z", "is_valid": True, "signature_algorithm": None, "san": ["tienda-demo.test"], "created_at": NOW},
            {"id": "c2", "host": "pruebas.tienda-demo.test", "issuer": None, "subject": None, "valid_from": None, "valid_to": None,
             "is_valid": False, "signature_algorithm": None, "san": [], "created_at": NOW},
        ],
        # Los mismos ocho hallazgos que da el motor verdadero con los sitios de práctica (2 altos, 1 medio, 5 bajos).
        "findings": [
            _finding("exposed_port", "high", "Database port exposed", f"Port 3306/tcp (mysql) is open on {STAGING_IP}.",
                     {"host": STAGING_IP, "port": 3306, "service": "mysql"}),
            _finding("insecure_tls", "high", "Invalid or expired TLS certificate", "The TLS certificate for pruebas.tienda-demo.test failed validation.",
                     {"host": "pruebas.tienda-demo.test"}),
            _finding("exposed_port", "medium", "SSH exposed", f"SSH (port 22) is open on {STAGING_IP}.", {"host": STAGING_IP, "port": 22}),
            _finding("information_disclosure", "low", "Server version disclosure", "version",
                     {"url": https("pruebas.tienda-demo.test/"), "server_header": "Apache/2.4.29 (Ubuntu)"}),
            _finding("missing_security_header", "low", "Missing content-security-policy header", "no csp",
                     {"url": https("pruebas.tienda-demo.test/"), "missing_header": "content-security-policy"}),
            _finding("missing_security_header", "low", "Missing x-frame-options header", "no xfo",
                     {"url": https("pruebas.tienda-demo.test/"), "missing_header": "x-frame-options"}),
            _finding("missing_security_header", "low", "Missing strict-transport-security header", "no hsts",
                     {"url": https("pruebas.tienda-demo.test/"), "missing_header": "strict-transport-security"}),
            _finding("missing_security_header", "low", "Missing content-security-policy header", "no csp",
                     {"url": https("tienda-demo.test/"), "missing_header": "content-security-policy"}),
        ],
    }


def result_staging_off() -> dict:
    result = result_staging_on()
    result["subdomains"][0]["resolved_ip"] = STAGING_IP
    result["ports"] = result["ports"][:1]
    result["http_fingerprints"] = result["http_fingerprints"][:1]
    result["technologies"] = result["technologies"][:1]
    result["tls_certificates"] = result["tls_certificates"][:1]
    result["findings"] = [result["findings"][7]]   # lo único que queda: a la tienda le falta una cabecera
    return result


class FakeEngine:
    """Estado del motor de mentira + el servidor HTTP que lo expone."""

    def __init__(self, shared_dir: Path, off_flag_name: str, token_file_name: str) -> None:
        self.shared_dir, self.off_flag_name, self.token_file_name = shared_dir, off_flag_name, token_file_name
        self.lock = threading.Lock()
        self.requests: list[tuple[str, str, Optional[dict], Optional[str]]] = []   # (método, camino, cuerpo, token)
        self.logins = 0
        self.registrations = 0
        self.reset_database()
        self.server: Optional[ThreadingHTTPServer] = None

    def reset_database(self) -> None:
        with self.lock:
            self.users: dict[str, dict] = {}
            self.tokens: dict[str, str] = {}
            self.domains: dict[str, dict] = {}
            self.scans: dict[str, dict] = {}

    # -- arranque -------------------------------------------------------------------------------------------------------
    def start(self) -> str:
        engine = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:  # silencio
                pass

            def _reply(self, status: int, payload=None, raw: Optional[bytes] = None) -> None:
                body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else b"")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else None
                path = self.path.split("?")[0]
                with engine.lock:
                    engine.requests.append((method, path, body, token))
                    status, payload, raw = engine.route(method, path, body, token)
                self._reply(status, payload, raw)

            def do_GET(self) -> None:  # noqa: N802
                self._handle("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._handle("POST")

            def do_DELETE(self) -> None:  # noqa: N802
                self._handle("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    # -- rutas ----------------------------------------------------------------------------------------------------------
    def route(self, method: str, path: str, body, token):
        assert path.startswith("/api/v1"), path
        path = path[len("/api/v1"):]
        unauthorized = (401, {"detail": "Not authenticated"}, None)

        if (method, path) == ("GET", "/health"):
            return 200, {"status": "ok", "version": "1.0.0"}, None
        if (method, path) == ("POST", "/auth/register"):
            if not body.get("tos_accepted"):
                return 422, {"detail": "Must accept Terms of Service"}, None
            if body["email"] in self.users:
                return 409, {"detail": "Email already registered"}, None
            self.registrations += 1
            self.users[body["email"]] = {"password": body["password"], "id": str(uuid.uuid4())}
            return 201, {"token": self._issue(body["email"]), "user": {"email": body["email"]}}, None
        if (method, path) == ("POST", "/auth/login"):
            self.logins += 1
            user = self.users.get(body["email"])
            if not user or user["password"] != body["password"]:
                return 401, {"detail": "Invalid email or password"}, None
            return 200, {"token": self._issue(body["email"]), "user": {"email": body["email"]}}, None

        email = self.tokens.get(token or "")
        if email is None:
            return unauthorized
        owner = self.users[email]["id"]

        if (method, path) == ("GET", "/domains"):
            return 200, {"domains": [d for d in self.domains.values() if d["user_id"] == owner]}, None
        if (method, path) == ("POST", "/domains"):
            if any(d["domain"] == body["domain"] for d in self.domains.values()):
                return 409, {"detail": "Domain already registered for your account"}, None
            domain_id = str(uuid.uuid4())
            self.domains[domain_id] = {
                "id": domain_id, "user_id": owner, "domain": body["domain"], "verification_status": "pending",
                "verification_method": "dns_txt", "verification_token": f"recon-verify-{uuid.uuid4()}", "verified_at": None,
            }
            return 201, {"domain_id": domain_id, "verification_token": self.domains[domain_id]["verification_token"]}, None

        parts = path.strip("/").split("/")
        if parts[0] == "domains" and len(parts) >= 2:
            domain = self.domains.get(parts[1])
            if domain is None or domain["user_id"] != owner:
                return 404, {"detail": "Domain not found"}, None
            if (method, len(parts)) == ("DELETE", 2):
                del self.domains[parts[1]]
                self.scans = {k: v for k, v in self.scans.items() if v["domain_id"] != parts[1]}
                return 204, None, None
            if (method, parts[2:]) == ("POST", ["verify"]):
                published = self._published_token()
                ok = published == domain["verification_token"]
                domain["verification_status"] = "verified" if ok else "failed"
                domain["verification_method"] = body["method"]
                if ok:
                    return 200, {"domain": dict(domain)}, None
                return 200, {"domain": dict(domain), "error": f"Verification failed via {body['method']}."}, None
            if (method, parts[2:]) == ("GET", ["history"]):
                return 200, [self._history_entry(s) for s in self.scans.values() if s["domain_id"] == parts[1]][::-1], None

        if (method, path) == ("POST", "/scans"):
            domain = self.domains.get(body["domain_id"])
            if domain is None or domain["user_id"] != owner:
                return 404, {"detail": "Domain not found"}, None
            if domain["verification_status"] != "verified":
                return 422, {"detail": "Domain not verified. Verify ownership before scanning."}, None
            job_id = str(uuid.uuid4())
            self.scans[job_id] = {"id": job_id, "domain_id": body["domain_id"], "user_id": owner, "polls": 0,
                                  "config": body, "staging_on": not (self.shared_dir / self.off_flag_name).exists()}
            return 201, {"job_id": job_id, "status": "queued"}, None
        if parts[0] == "scans" and len(parts) in (2, 4):
            scan = self.scans.get(parts[1])
            if scan is None or scan["user_id"] != owner:
                return 404, {"detail": "Scan not found"}, None
            if len(parts) == 2:
                scan["polls"] += 1
                return 200, self._detail(scan), None
            if parts[2:] == ["export", "json"]:
                scan["polls"] = max(scan["polls"], 2)
                return 200, None, json.dumps(self._detail(scan), indent=2).encode()
        return 404, {"detail": "Not Found"}, None

    # -- ayudas ---------------------------------------------------------------------------------------------------------
    def _issue(self, email: str) -> str:
        token = f"token-{uuid.uuid4()}"
        self.tokens[token] = email
        return token

    def _published_token(self) -> Optional[str]:
        try:
            return (self.shared_dir / self.token_file_name).read_text().strip()
        except OSError:
            return None

    def _job(self, scan: dict) -> dict:
        done = scan["polls"] >= 2
        return {
            "id": scan["id"], "domain_id": scan["domain_id"], "user_id": scan["user_id"], "target": "tienda-demo.test",
            "status": "completed" if done else "running", "progress": 100 if done else 50, "config": scan["config"],
            "error_message": None, "started_at": NOW, "completed_at": NOW if done else None, "created_at": NOW, "updated_at": NOW,
        }

    def _detail(self, scan: dict) -> dict:
        job = self._job(scan)
        base = {"job": job, "subdomains": [], "ports": [], "http_fingerprints": [], "technologies": [], "tls_certificates": [], "findings": []}
        if job["status"] == "completed":
            base.update(result_staging_on() if scan["staging_on"] else result_staging_off())
        return base

    def _history_entry(self, scan: dict) -> dict:
        job = self._job(scan)
        detail = self._detail(scan)
        counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for finding in detail["findings"]:
            counts[finding["severity"]] += 1
        return {"id": scan["id"], "status": job["status"], "created_at": NOW, "completed_at": job["completed_at"], "config": scan["config"],
                "subdomains_count": len(detail["subdomains"]), "open_ports_count": len(detail["ports"]), "findings_by_severity": counts}
