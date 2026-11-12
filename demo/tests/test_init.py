"""init.py: credenciales, autoridad de certificación de práctica y carpeta compartida."""
import datetime as dt
import os
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import init
from common import OFF_FLAG, ROLES, TOKEN_FILE


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(init, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(init, "SHARED_DIR", tmp_path / "shared")
    (tmp_path / "state").mkdir()
    return tmp_path


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def test_secrets_are_created_once_and_kept(isolated):
    assert init.ensure_secrets() is True
    first = {p.name: p.read_text() for p in (isolated / "state").iterdir() if p.is_file()}
    assert set(first) == {"postgres_password", "jwt_secret", "demo_password"}
    assert init.ensure_secrets() is False   # la segunda vez no toca nada
    assert {p.name: p.read_text() for p in (isolated / "state").iterdir() if p.is_file()} == first


def test_secrets_meet_the_engine_rules(isolated):
    init.ensure_secrets()
    jwt = (isolated / "state" / "jwt_secret").read_text().strip()
    # Las mismas reglas que apps/engine/app/config.py aplica a JWT_SECRET.
    assert len(jwt) >= 32 and len(set(jwt)) >= 8
    assert not any(marker in jwt.lower() for marker in init.EXAMPLE_MARKERS)
    password = (isolated / "state" / "demo_password").read_text().strip()
    assert 8 <= len(password.encode()) <= 72   # reglas de RegisterRequest
    assert "\x00" not in password


def test_secret_files_are_world_readable_but_not_writable(isolated):
    init.ensure_secrets()
    for path in (isolated / "state").iterdir():
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o644, (path.name, oct(mode))   # las leen la base, el motor y la consola, cada uno con su usuario


def test_pki_has_all_files_and_the_chain_is_right(isolated):
    assert init.ensure_pki(now()) is True
    pki = isolated / "state" / "pki"
    ca = x509.load_pem_x509_certificate((pki / "ca.pem").read_bytes())
    for role in ROLES:
        leaf = x509.load_pem_x509_certificate((pki / f"{role}.pem").read_bytes())
        leaf.verify_directly_issued_by(ca)   # lanza si no la firmó la autoridad de la demo
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert len(san.get_values_for_type(x509.DNSName)) == 1
        assert (pki / f"{role}.key").is_file()


def test_certificate_names_and_validity(isolated):
    init.ensure_pki(now())
    pki = isolated / "state" / "pki"
    load = lambda role: x509.load_pem_x509_certificate((pki / f"{role}.pem").read_bytes())  # noqa: E731
    names = {role: load(role).extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)[0]
             for role in ROLES}
    assert names == {"shop": "tienda-demo.test", "staging": "pruebas.tienda-demo.test", "ct": "crt.sh"}
    assert load("shop").not_valid_after_utc > now() + dt.timedelta(days=300)
    assert load("ct").not_valid_after_utc > now() + dt.timedelta(days=300)
    assert load("staging").not_valid_after_utc < now()   # vencido a propósito


def test_the_ca_private_key_is_discarded(isolated):
    init.ensure_pki(now())
    pki = isolated / "state" / "pki"
    assert not (pki / "ca.key").exists()
    ca = x509.load_pem_x509_certificate((pki / "ca.pem").read_bytes())
    ca_public = ca.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    keys = [p for p in pki.iterdir() if b"PRIVATE KEY" in p.read_bytes()]
    assert sorted(p.name for p in keys) == sorted(f"{role}.key" for role in ROLES)
    for key_file in keys:   # ninguna clave guardada es la de la autoridad: con ellas no se puede emitir más certificados
        private = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        assert public != ca_public


def test_private_keys_are_not_readable_by_others(isolated):
    init.ensure_pki(now())
    for role in ROLES:
        mode = stat.S_IMODE((isolated / "state" / "pki" / f"{role}.key").stat().st_mode)
        assert mode == 0o600


def test_pki_is_kept_when_current_and_renewed_when_needed(isolated):
    assert init.ensure_pki(now()) is True
    assert init.ensure_pki(now()) is False   # sigue vigente: no se toca
    ca_before = (isolated / "state" / "pki" / "ca.pem").read_bytes()
    assert init.ensure_pki(now() + dt.timedelta(days=345)) is True   # a menos de 30 días de vencer: se renueva
    assert (isolated / "state" / "pki" / "ca.pem").read_bytes() != ca_before


def test_pki_is_rebuilt_when_a_file_is_missing_or_broken(isolated):
    init.ensure_pki(now())
    pki = isolated / "state" / "pki"
    (pki / "ct.key").unlink()
    assert init.ensure_pki(now()) is True
    (pki / "shop.pem").write_text("no es un certificado")
    assert init.ensure_pki(now()) is True
    assert init.ensure_pki(now()) is False


def test_shared_folder_starts_clean_every_time(isolated):
    shared = isolated / "shared"
    shared.mkdir()
    (shared / TOKEN_FILE).write_text("recon-verify-viejo")
    (shared / OFF_FLAG).write_text("off")
    init.reset_shared()
    assert sorted(p.name for p in shared.iterdir()) == []
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755


def test_main_prints_no_secret(isolated, capsys):
    assert init.main() == 0
    out = capsys.readouterr().out
    for name in ("postgres_password", "jwt_secret", "demo_password"):
        assert (isolated / "state" / name).read_text().strip() not in out
    assert "generadas" in out


def test_init_only_needs_cryptography_not_the_engine():
    source = Path(init.__file__).read_text(encoding="utf-8")
    assert "from app" not in source and "import app" not in source   # no toca el código del motor
    assert os.path.basename(init.__file__) == "init.py"
