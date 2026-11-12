"""Nombres y archivos que comparten `init.py`, `practice.py` y la consola. Solo constantes: nada que ejecutar."""

# El dominio "del cliente" de la demo. `.test` está reservado para pruebas (RFC 6761): no existe en internet.
DOMAIN = "tienda-demo.test"
STAGING_HOST = f"pruebas.{DOMAIN}"
# El registro público de certificados que consulta el motor para descubrir subdominios. En la demo lo contesta un sitio de
# práctica con ese mismo nombre dentro de la red de la demo: el motor nunca llega al verdadero.
CT_HOST = "crt.sh"

ROLES = ("shop", "staging", "ct")
ROLE_HOSTS = {"shop": DOMAIN, "staging": STAGING_HOST, "ct": CT_HOST}

# Carpeta compartida (la consola escribe, los sitios de práctica leen).
TOKEN_FILE = "verification-token.txt"   # el contenido que el motor espera encontrar en /.well-known/recon-verification.txt
OFF_FLAG = "staging-off"                # si existe, el servidor de pruebas está apagado

DEFAULT_STATE_DIR = "/run/demo"       # credenciales y certificados (solo lectura para todos menos init)
DEFAULT_SHARED_DIR = "/run/shared"    # estado que cambian los botones de la consola

VERIFICATION_PATH = "/.well-known/recon-verification.txt"
