"""La prueba de humo (smoke.py) contra la consola de verdad, con el motor de mentira. La corrida contra el motor verdadero está en README.md."""
from __future__ import annotations

import http.client
import runpy
import sys
import types
from pathlib import Path

import pytest

import smoke
from common import OFF_FLAG, TOKEN_FILE


def run_smoke(console, **overrides):
    lines: list[str] = []
    options = {"poll": 0.01, "settle": 0.0, "wait": 5.0, "scan_timeout": 10.0}
    options.update(overrides)
    code = smoke.run(console.port, out=lines.append, **options)
    return code, "\n".join(lines)


def test_the_whole_walkthrough_passes_and_leaves_the_demo_clean(console):
    code, output = run_smoke(console)
    assert code == 0, output
    assert f"[ok] {smoke.TOTAL_STEPS:>2}/{smoke.TOTAL_STEPS}" in output       # contó todos los pasos
    assert "RESULTADO: todo en orden" in output
    assert smoke.SUMMARY_WITH_STAGING in output and smoke.SUMMARY_WITHOUT_STAGING in output
    state = console.state()
    assert (state["account"], state["domain"], state["file_published"], state["staging_on"]) == (True, None, False, True)
    assert not (console.config.shared_dir / TOKEN_FILE).exists() and not (console.config.shared_dir / OFF_FLAG).exists()


def test_it_uses_exactly_two_scans_so_it_can_be_repeated_within_the_hourly_limit(console):
    assert run_smoke(console)[0] == 0
    scans = [r for r in console.engine.requests if (r[0], r[1]) == ("POST", "/api/v1/scans") and r[2]["port_range"] == "top-100"]
    # 1 intento rechazado (dominio sin verificar) + 2 escaneos. El motor permite 10 por hora.
    assert len(scans) == 3
    assert console.engine.requests and all(r[1].startswith("/api/v1") for r in console.engine.requests)


def test_it_can_be_run_twice_in_a_row(console):
    assert run_smoke(console)[0] == 0
    assert run_smoke(console)[0] == 0


def test_it_starts_from_whatever_state_the_demo_was_left_in(console):
    console.verified()                                  # alguien dejó la demo a medias: dominio verificado y archivo publicado
    assert console.post("/api/staging", {"on": False})[0] == 200
    assert run_smoke(console)[0] == 0


def test_a_wrong_result_fails_and_says_what_was_expected_and_cleans_up(console, monkeypatch):
    monkeypatch.setattr(smoke, "SUMMARY_WITH_STAGING", "9 altos")
    code, output = run_smoke(console)
    assert code == 1
    assert "[FALLA] paso 8/11" in output and "9 altos" in output and "2 altos, 1 medio, 5 bajos" in output
    assert "docker compose logs" in output
    assert "La demo se reinició para no dejarla a medias." in output
    state = console.state()
    assert state["domain"] is None and state["staging_on"] is True and state["file_published"] is False


def test_a_failed_verification_is_reported_instead_of_hanging(console):
    # Si el archivo de verificación no llegara a publicarse, la prueba lo dice en ese paso.
    original = console.demo.publish_file
    console.demo.publish_file = lambda publish: None
    try:
        code, output = run_smoke(console)
    finally:
        console.demo.publish_file = original
    assert code == 1
    assert "[FALLA] paso 7/11" in output and "archivo de verificación" in output


def test_a_slow_scan_gives_up_with_a_clear_message(console, monkeypatch):
    monkeypatch.setattr(console.demo, "scan_view", lambda job_id: {"job": {"status": "running", "progress": 10}})
    code, output = run_smoke(console, scan_timeout=0.2)
    assert code == 1 and "no terminó en 0 segundos" in output


def test_a_failed_scan_shows_the_engines_error(console, monkeypatch):
    monkeypatch.setattr(console.demo, "scan_view", lambda job_id: {"job": {"status": "failed", "error_message": "se acabó el tiempo"}})
    code, output = run_smoke(console)
    assert code == 1 and "El escaneo falló" in output and "se acabó el tiempo" in output


def test_without_a_console_it_says_how_to_turn_the_demo_on(console):
    console.http_server.shutdown()
    console.http_server.server_close()
    code, output = run_smoke(console)
    assert code == 1
    assert "No se pudo hablar con la consola" in output and "docker compose up --build" in output
    assert "La demo se reinició" not in output          # sin consola no hay nada que reiniciar


def test_it_waits_for_the_engine_and_gives_up_if_it_never_starts(console):
    console.engine.stop()                               # el motor no contesta: la consola dice engine_ready = false
    code, output = run_smoke(console, wait=0.3)
    assert code == 1
    assert "Esperando que el motor termine de arrancar" in output and "El motor no estuvo listo" in output


def test_it_only_talks_to_the_local_console(console, monkeypatch):
    hosts = []
    real = http.client.HTTPConnection

    def spy(host, *args, **kwargs):
        hosts.append(host)
        return real(host, *args, **kwargs)

    # Se cambia solo lo que ve smoke.py (el resto del programa, incluida la consola, sigue usando http.client de verdad).
    local = types.SimpleNamespace(client=types.SimpleNamespace(HTTPConnection=spy, HTTPException=http.client.HTTPException))
    monkeypatch.setattr(smoke, "http", local)
    assert run_smoke(console)[0] == 0
    assert hosts and set(hosts) == {"127.0.0.1"}


def test_it_announces_that_it_accepts_the_demo_terms_on_behalf_of_whoever_runs_it(console):
    _, output = run_smoke(console)
    assert "acepta los términos de la demo en nombre de quien la corre" in output
    assert "EN NOMBRE DE QUIEN LA CORRE" in smoke.__doc__


def test_the_script_runs_as_a_program_and_only_needs_the_standard_library(console, capsys, monkeypatch):
    source = Path(smoke.__file__).read_text(encoding="utf-8")
    imported = {line.split()[1].split(".")[0] for line in source.splitlines() if line.startswith(("import ", "from "))}
    stdlib = getattr(sys, "stdlib_module_names", None)       # existe desde Python 3.10
    if stdlib:
        assert imported <= set(stdlib) | {"__future__"}, imported - set(stdlib)
    monkeypatch.setattr(sys, "argv", ["smoke.py", "--port", str(console.port), "--poll", "0.01", "--settle", "0"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(smoke.__file__, run_name="__main__")
    assert exit_info.value.code == 0
    assert "RESULTADO: todo en orden" in capsys.readouterr().out


def test_help_is_in_spanish_and_lists_the_options(capsys):
    with pytest.raises(SystemExit) as exit_info:
        smoke.main(["--help"])
    assert exit_info.value.code == 0
    text = capsys.readouterr().out
    assert "--port" in text and "puerto de la consola" in text and "--scan-timeout" in text
