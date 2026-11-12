"""Prepara lo que la demo necesita antes de arrancar: credenciales, certificados de práctica y la carpeta compartida.

Nada de esto vive en el repositorio: cada computadora lo genera la primera vez que arranca la demo y lo guarda en volúmenes de
Docker. Si ya existe, no se toca (salvo los certificados, que se renuevan solos antes de vencer, y el estado de los botones de la
consola, que empieza limpio en cada encendido). `docker compose down -v` borra los volúmenes y la próxima vez se genera todo de nuevo.

Autoridad de certificación de práctica
--------------------------------------
Recon Scope verifica la propiedad de un dominio pidiéndole a su sitio, por HTTPS, un archivo con un código. Para que eso funcione
sin internet, los sitios de práctica presentan certificados firmados por una autoridad de la demo, y el motor la reconoce solo a
ella (variable SSL_CERT_FILE): sigue verificando certificados igual que siempre, no se desactiva ninguna comprobación. La clave
privada de esa autoridad se descarta apenas termina de firmar: no queda forma de emitir más certificados de confianza.

Uno de los certificados (el del servidor de pruebas olvidado) se emite ya vencido, a propósito: es uno de los hallazgos de la demo.

No imprime ninguna credencial.
"""
from __future__ import annotations

import datetime as dt
import os
import secrets
import sys
from pathlib import Path

from common import DEFAULT_SHARED_DIR, DEFAULT_STATE_DIR, OFF_FLAG, ROLE_HOSTS, ROLES, TOKEN_FILE

STATE_DIR = Path(os.environ.get("DEMO_STATE_DIR", DEFAULT_STATE_DIR))
SHARED_DIR = Path(os.environ.get("DEMO_SHARED_DIR", DEFAULT_SHARED_DIR))
DEMO_UID = int(os.environ.get("DEMO_UID", "10002"))   # el usuario sin privilegios con el que corren la consola y los sitios

ORGANIZATION = "Recon Scope Demo"
RENEW_BEFORE = dt.timedelta(days=30)

# Los mismos fragmentos que rechaza el motor (apps/engine/app/config.py) en JWT_SECRET. Un valor al azar casi nunca los trae,
# pero si pasara, el motor se negaría a arrancar: por eso se comprueban acá también.
EXAMPLE_MARKERS = (
    "change-me", "change_me", "changeme", "example", "placeholder", "your-secret", "your_secret",
    "secret-here", "secret_here", "supersecret", "super-secret",
)


# -- archivos -------------------------------------------------------------------------------------------------------------

def _chown(path: Path) -> None:
    if os.geteuid() == 0:   # solo root puede cambiar el dueño (en las pruebas, que no corren como root, no hace falta)
        os.chown(path, DEMO_UID, DEMO_UID)


def write_atomic(path: Path, data: bytes, *, mode: int, owned_by_demo: bool = False) -> None:
    """Escribe en un archivo temporal y lo mueve al lugar final: quien lee nunca ve un archivo a medias."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    if owned_by_demo:
        _chown(tmp)
    os.replace(tmp, path)


# -- credenciales ---------------------------------------------------------------------------------------------------------

def is_strong(value: str, min_length: int, min_distinct: int) -> bool:
    return (
        len(value) >= min_length
        and len(set(value)) >= min_distinct
        and not any(marker in value.lower() for marker in EXAMPLE_MARKERS)
    )


def new_token(nbytes: int, min_length: int = 32) -> str:
    while True:
        value = secrets.token_urlsafe(nbytes)
        if is_strong(value, min_length, 8):
            return value


def write_secret_if_missing(name: str, make) -> bool:
    path = STATE_DIR / name
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return False
    # 0644: las leen la base, el motor y la consola, cada uno con su propio usuario, y el volumen no sale de la demo.
    write_atomic(path, (make() + "\n").encode("utf-8"), mode=0o644)
    return True


def ensure_secrets() -> bool:
    created = [
        write_secret_if_missing("postgres_password", lambda: secrets.token_hex(24)),
        write_secret_if_missing("jwt_secret", lambda: new_token(48)),
        write_secret_if_missing("demo_password", lambda: new_token(18, min_length=16)),
    ]
    return any(created)


# -- certificados ---------------------------------------------------------------------------------------------------------

def pki_is_current(pki_dir: Path, now: dt.datetime) -> bool:
    """¿Están todos los archivos, firmados por la autoridad que hay, y el de la tienda tiene vida por delante?"""
    from cryptography import x509

    try:
        ca = x509.load_pem_x509_certificate((pki_dir / "ca.pem").read_bytes())
        leaves = {}
        for role in ROLES:
            leaf = x509.load_pem_x509_certificate((pki_dir / f"{role}.pem").read_bytes())
            leaf.verify_directly_issued_by(ca)
            if not (pki_dir / f"{role}.key").is_file():
                return False
            leaves[role] = leaf
        return (
            leaves["shop"].not_valid_after_utc - now > RENEW_BEFORE
            and leaves["staging"].not_valid_after_utc < now   # el vencido tiene que seguir vencido
        )
    except Exception:  # noqa: BLE001 - cualquier problema con los archivos: se generan de nuevo
        return False


def generate_pki(pki_dir: Path, now: dt.datetime) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    def name(common_name: str) -> x509.Name:
        return x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = name("Recon Scope Demo CA")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # (desde cuándo, hasta cuándo): la tienda y el registro de certificados, vigentes; el servidor de pruebas, vencido hace mes y medio.
    validity = {
        "shop": (now - dt.timedelta(days=30), now + dt.timedelta(days=365)),
        "ct": (now - dt.timedelta(days=30), now + dt.timedelta(days=365)),
        "staging": (now - dt.timedelta(days=800), now - dt.timedelta(days=45)),
    }
    pki_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(pki_dir, 0o755)
    for role in ROLES:
        hostname = ROLE_HOSTS[role]
        not_before, not_after = validity[role]
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(name(hostname)).issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        write_atomic(
            pki_dir / f"{role}.key",
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
            mode=0o600, owned_by_demo=True,
        )
        write_atomic(pki_dir / f"{role}.pem", cert.public_bytes(serialization.Encoding.PEM), mode=0o644)
    # La autoridad va última: mientras falte, `pki_is_current` dice que no y se vuelve a generar todo. Su clave privada se
    # descarta acá (`ca_key` no se guarda en ningún lado).
    write_atomic(pki_dir / "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM), mode=0o644)


def ensure_pki(now: dt.datetime | None = None) -> bool:
    now = now or dt.datetime.now(dt.timezone.utc)
    pki_dir = STATE_DIR / "pki"
    if pki_is_current(pki_dir, now):
        return False
    generate_pki(pki_dir, now)
    return True


# -- carpeta compartida ---------------------------------------------------------------------------------------------------

def reset_shared() -> None:
    """La consola escribe acá y los sitios de práctica leen. Cada encendido empieza limpio: la base también empieza vacía."""
    SHARED_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SHARED_DIR, 0o755)
    _chown(SHARED_DIR)
    for name in (TOKEN_FILE, OFF_FLAG):
        (SHARED_DIR / name).unlink(missing_ok=True)


def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o755)
    secrets_created = ensure_secrets()
    pki_created = ensure_pki()
    reset_shared()
    print("Credenciales de la demo: " + ("generadas." if secrets_created else "ya existían, se conservan."), flush=True)
    print("Certificados de práctica: " + ("generados." if pki_created else "ya existían, se conservan."), flush=True)
    print("Estado de los botones de la consola: limpio.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
