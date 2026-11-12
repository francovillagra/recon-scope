"""Prueba de humo de la demo de Recon Scope: recorre toda la demo a través de la consola, como lo haría alguien con el navegador.

Se corre con la demo encendida (`docker compose up --build`, dentro de la carpeta demo) y desde cualquier carpeta:

    python demo/tests/smoke.py                  # la consola en el puerto 4100
    python demo/tests/smoke.py --port 4200      # si se cambió DEMO_CONSOLE_PORT

Usa solo la biblioteca estándar de Python (3.8 o más nueva): no hace falta instalar nada. Habla únicamente con la consola de la demo
(127.0.0.1); nunca con otra dirección.

Qué comprueba, en este orden (usa el motor verdadero, no uno de mentira):
  1. el motor responde;  2. la demo parte de cero;  3. se crea la cuenta de práctica;  4. se registra el dominio;
  5. el motor se niega a escanear un dominio sin verificar;  6. la verificación falla mientras el archivo no está publicado;
  7. con el archivo publicado, la propiedad queda demostrada;  8. el escaneo encuentra 2 hallazgos altos, 1 medio y 5 bajos
     (puerto de base de datos abierto, certificado vencido, SSH, etc. del servidor de pruebas);
  9. al apagar el servidor de pruebas, un segundo escaneo deja solo 1 hallazgo bajo;  10. el informe se descarga;
  11. la demo vuelve a cero.
Son 2 escaneos: el motor permite 10 por hora, así que se puede repetir varias veces seguidas.

AVISO: esta prueba acepta los términos de la demo EN NOMBRE DE QUIEN LA CORRE (son los que muestra la consola: una cuenta de práctica
local, solo con los sitios de práctica, que se borra al apagar la demo). Es a propósito: está pensada para que la corra el dueño de la
demo en su propia computadora. Al empezar y al terminar reinicia la demo (borra el dominio y los escaneos de práctica; la cuenta
de práctica se conserva).

Termina con código 0 si todo salió como se esperaba y con 1 si algo falló (y dice qué).
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import sys
import time
from typing import Any, Optional

DOMAIN = "tienda-demo.test"
STAGING = f"pruebas.{DOMAIN}"
SUMMARY_WITH_STAGING = "2 altos, 1 medio, 5 bajos"
SUMMARY_WITHOUT_STAGING = "1 bajo"
STAGING_PORTS = {21, 22, 3306}     # FTP, SSH y base de datos del servidor de pruebas
TOTAL_STEPS = 11


class Failure(Exception):
    """Algo no salió como se esperaba. El mensaje dice qué, para quien está mirando la pantalla."""


class ConsoleDown(Failure):
    pass


class Client:
    """Hace los mismos pedidos que la página de la consola (con su Host y su Origin) y devuelve (estado, cuerpo)."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.base = f"http://localhost:{port}"
        self.headers = {"Host": f"localhost:{port}", "Origin": self.base}

    def call(self, method: str, path: str, body: Optional[dict] = None, timeout: float = 60.0) -> tuple[int, Any]:
        headers = dict(self.headers)
        payload = None
        if method == "POST":
            payload = json.dumps(body or {}).encode()
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            connection.request(method, path, payload, headers)
            response = connection.getresponse()
            raw = response.read()
        except socket.timeout:
            raise ConsoleDown(
                f"La consola ({self.base}) no contestó a tiempo. Puede estar ocupada: esperar un momento y repetir la prueba."
            ) from None
        except (OSError, http.client.HTTPException) as exc:
            raise ConsoleDown(
                f"No se pudo hablar con la consola en {self.base} ({exc.__class__.__name__}). "
                "¿Está encendida la demo? Se enciende con:  cd demo  y después  docker compose up --build"
            ) from None
        finally:
            connection.close()
        try:
            return response.status, json.loads(raw)
        except ValueError:
            return response.status, raw


class Smoke:
    def __init__(self, client: Client, poll: float, settle: float, wait: float, scan_timeout: float, out=print) -> None:
        self.client, self.poll, self.settle, self.wait, self.scan_timeout = client, poll, settle, wait, scan_timeout
        self.out = out
        self.step_number = 0
        self.started = time.monotonic()

    # -- ayudas ------------------------------------------------------------------------------------------------------------
    def ok(self, text: str) -> None:
        self.step_number += 1
        self.out(f"[ok] {self.step_number:>2}/{TOTAL_STEPS}  {text}")

    def expect(self, condition: bool, what: str, got: Any = None) -> None:
        if not condition:
            detail = f"\n         Se obtuvo: {got}" if got is not None else ""
            raise Failure(f"{what}{detail}")

    def post(self, path: str, body: Optional[dict] = None, expected: int = 200) -> Any:
        status, payload = self.client.call("POST", path, body)
        self.expect(status == expected, f"POST {path} debía responder {expected}", f"{status} {_short(payload)}")
        return payload

    def state(self) -> dict:
        status, payload = self.client.call("GET", "/api/state")
        self.expect(status == 200 and isinstance(payload, dict), "GET /api/state debía responder 200", f"{status} {_short(payload)}")
        return payload

    def scan(self, port_range: str) -> tuple[str, dict]:
        started = self.post("/api/scan", {"port_range": port_range})
        job_id = started.get("job_id") if isinstance(started, dict) else None
        self.expect(bool(job_id), "El escaneo debía devolver un identificador", started)
        deadline = time.monotonic() + self.scan_timeout
        while True:
            status, view = self.client.call("GET", f"/api/scan/{job_id}")
            self.expect(status == 200 and isinstance(view, dict), f"GET /api/scan/{job_id} debía responder 200", f"{status} {_short(view)}")
            state = view["job"]["status"]
            if state == "completed":
                return job_id, view
            self.expect(state != "failed", "El escaneo falló", view["job"].get("error_message"))
            self.expect(time.monotonic() < deadline, f"El escaneo no terminó en {self.scan_timeout:.0f} segundos", state)
            time.sleep(self.poll)

    # -- el recorrido ------------------------------------------------------------------------------------------------------
    def run(self) -> None:
        self.out(f"Prueba de humo de la demo de Recon Scope (consola en {self.client.base})")
        self.out("Aviso: acepta los términos de la demo en nombre de quien la corre y reinicia la demo al empezar y al terminar.\n")

        self.wait_for_engine()
        self.start_from_zero()
        self.create_account_and_domain()
        self.prove_ownership()
        first_job = self.scan_with_staging()
        self.scan_without_staging(first_job)
        self.finish_clean()

    def wait_for_engine(self) -> None:
        deadline = time.monotonic() + self.wait
        announced = False
        while True:
            if self.state().get("engine_ready") is True:
                break
            if not announced:
                self.out("      Esperando que el motor termine de arrancar (la primera vez tarda un poco)...")
                announced = True
            self.expect(time.monotonic() < deadline, f"El motor no estuvo listo en {self.wait:.0f} segundos")
            time.sleep(min(2.0, max(self.poll, 0.02)))
        self.ok("El motor responde.")

    def start_from_zero(self) -> None:
        self.post("/api/reset")
        state = self.state()
        self.expect(state["domain"] is None and state["file_published"] is False and state["staging_on"] is True,
                    "Después de reiniciar, la demo debía quedar sin dominio, sin archivo y con el servidor de pruebas encendido",
                    {key: state[key] for key in ("domain", "file_published", "staging_on")})
        self.ok("La demo parte de cero (sin dominio, sin archivo publicado, servidor de pruebas encendido).")

    def create_account_and_domain(self) -> None:
        self.post("/api/account", {"accept_terms": True})
        self.expect(self.state()["account"] is True, "Después de crear la cuenta, el estado debía mostrarla")
        self.ok("Cuenta de práctica creada (con los términos de la demo aceptados por quien corre la prueba).")

        self.post("/api/domain")
        domain = self.state()["domain"]
        self.expect(isinstance(domain, dict) and domain.get("status") != "verified" and str(domain.get("token", "")).startswith("recon-verify-"),
                    "El dominio debía quedar registrado, sin verificar y con su código de verificación", domain and domain.get("status"))
        self.ok(f"Dominio {DOMAIN} registrado, todavía sin verificar.")

    def prove_ownership(self) -> None:
        refused = self.post("/api/try-scan")
        self.expect(isinstance(refused, dict) and refused.get("refused") is True,
                    "El motor debía negarse a escanear un dominio sin verificar", refused)
        self.ok("El motor se negó a escanear el dominio sin verificar.")

        before = self.post("/api/verify")
        self.expect(before == {"verified": False}, "Sin el archivo publicado, la verificación debía fallar", before)
        self.ok("Sin el archivo de verificación en el sitio, el motor no da por demostrada la propiedad.")

        self.post("/api/file", {"publish": True})
        state = self.state()
        self.expect(state["file_published"] is True, "El archivo de verificación debía figurar como publicado", state["file_published"])
        after = self.post("/api/verify")
        self.expect(after == {"verified": True}, "Con el archivo publicado, la verificación debía dar verdadero", after)
        self.expect(self.state()["domain"]["status"] == "verified", "El dominio debía quedar como verificado")
        self.ok("Archivo publicado en el sitio de práctica: propiedad demostrada (el motor lo pidió por HTTPS con certificado válido).")

    def scan_with_staging(self) -> str:
        job_id, view = self.scan("top-100")
        self.expect(view["summary"] == SUMMARY_WITH_STAGING, f"El primer escaneo debía resumirse como «{SUMMARY_WITH_STAGING}»",
                    f"«{view['summary']}»  {[f['title'] for f in view['findings']]}")
        hostnames = [s["hostname"] for s in view["subdomains"]]
        self.expect(STAGING in hostnames, f"El escaneo debía descubrir el subdominio {STAGING}", hostnames)
        staging_ports = {p["port"] for p in view["ports"] if p["name"] == STAGING}
        self.expect(STAGING_PORTS <= staging_ports, f"El servidor de pruebas debía mostrar abiertos los puertos {sorted(STAGING_PORTS)}", sorted(staging_ports))
        tls = {t["host"]: t["valid"] for t in view["tls"]}
        self.expect(tls.get(DOMAIN) is True and tls.get(STAGING) is False,
                    "La tienda debía tener certificado válido y el servidor de pruebas uno inválido", tls)
        self.ok(f"Escaneo con el servidor de pruebas encendido: {view['summary']} (subdominio, puertos {sorted(STAGING_PORTS)} y certificado vencido).")
        return job_id

    def scan_without_staging(self, first_job: str) -> None:
        self.post("/api/staging", {"on": False})
        time.sleep(self.settle)   # el sitio de práctica mira cada medio segundo si lo apagaron
        self.expect(self.state()["staging_on"] is False, "El estado debía mostrar el servidor de pruebas apagado")
        job_id, view = self.scan("top-100")
        self.expect(view["summary"] == SUMMARY_WITHOUT_STAGING, f"Con el servidor de pruebas apagado, el escaneo debía resumirse como «{SUMMARY_WITHOUT_STAGING}»",
                    f"«{view['summary']}»  {[f['title'] for f in view['findings']]}")
        still_open = sorted({p["port"] for p in view["ports"] if p["name"] == STAGING} & STAGING_PORTS)
        self.expect(not still_open, "Con el servidor de pruebas apagado no debía quedar ningún puerto suyo abierto", still_open)
        self.ok(f"Servidor de pruebas apagado y escaneado de nuevo: {view['summary']}.")

        status, report = self.client.call("GET", f"/api/report/{first_job}")
        self.expect(status == 200 and isinstance(report, dict) and report, "El informe del primer escaneo debía descargarse como JSON", f"{status}")
        history = self.state()["history"]
        self.expect(len(history) == 2, "El historial debía mostrar los dos escaneos", len(history))
        self.ok("El informe del primer escaneo se descarga (JSON) y el historial muestra los dos escaneos.")

    def finish_clean(self) -> None:
        self.post("/api/staging", {"on": True})
        self.post("/api/reset")
        state = self.state()
        self.expect(state["account"] is True and state["domain"] is None and state["file_published"] is False and state["staging_on"] is True,
                    "Al terminar, la demo debía quedar sin dominio, sin archivo y con el servidor de pruebas encendido",
                    {key: state[key] for key in ("account", "domain", "file_published", "staging_on")})
        self.ok("La demo quedó reiniciada (la cuenta de práctica se conserva).")


def _short(payload: Any) -> str:
    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False)
    return text if len(text) <= 240 else text[:240] + "…"


def run(port: int, poll: float = 1.0, settle: float = 1.5, wait: float = 180.0, scan_timeout: float = 180.0, out=print) -> int:
    client = Client(port)
    smoke = Smoke(client, poll, settle, wait, scan_timeout, out)
    try:
        smoke.run()
    except Failure as failure:
        out(f"[FALLA] paso {smoke.step_number + 1}/{TOTAL_STEPS}: {failure}")
        if not isinstance(failure, ConsoleDown):
            out("\nPara ver qué pasó:  docker compose logs --tail 80 console engine")
            _best_effort_cleanup(client, out)
        return 1
    except (KeyError, TypeError, ValueError, IndexError) as exc:   # una respuesta con otra forma de la esperada
        out(f"[FALLA] paso {smoke.step_number + 1}/{TOTAL_STEPS}: la consola devolvió algo con un formato inesperado ({exc.__class__.__name__}: {exc})")
        out("\nPara ver qué pasó:  docker compose logs --tail 80 console engine")
        _best_effort_cleanup(client, out)
        return 1
    out(f"\nRESULTADO: todo en orden ({smoke.step_number} comprobaciones, {time.monotonic() - smoke.started:.0f} segundos).")
    return 0


def _best_effort_cleanup(client: Client, out) -> None:
    """Si la prueba se cortó a la mitad, deja la demo de nuevo en cero (servidor de pruebas encendido, sin archivo ni dominio)."""
    try:
        client.call("POST", "/api/staging", {"on": True}, timeout=15)
        client.call("POST", "/api/reset", timeout=15)
        out("La demo se reinició para no dejarla a medias.")
    except Failure:
        out("No se pudo reiniciar la demo: usar «Reiniciar el recorrido» en la consola.")


def main(argv: Optional[list[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):   # que una consola de Windows con otra codificación no corte la prueba por una tilde
            stream.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Prueba de humo de la demo local de Recon Scope (ver el comienzo de este archivo).")
    parser.add_argument("--port", type=int, default=int(os.environ.get("DEMO_CONSOLE_PORT", "4100")), help="puerto de la consola (por defecto 4100)")
    parser.add_argument("--poll", type=float, default=1.0, help="segundos entre consultas mientras corre un escaneo")
    parser.add_argument("--settle", type=float, default=1.5, help="segundos de espera después de apagar el servidor de pruebas")
    parser.add_argument("--wait", type=float, default=180.0, help="segundos máximos esperando que el motor arranque")
    parser.add_argument("--scan-timeout", type=float, default=180.0, help="segundos máximos por escaneo")
    args = parser.parse_args(argv)
    return run(args.port, args.poll, args.settle, args.wait, args.scan_timeout)


if __name__ == "__main__":
    sys.exit(main())
