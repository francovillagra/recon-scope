"""El compose: las garantías de seguridad de la demo no dependen de que alguien se acuerde de ellas; se verifican acá."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from common import DOMAIN, ROLE_HOSTS  # noqa: E402

DEMO_DIR = Path(__file__).resolve().parent.parent
PRACTICE = ("shop", "staging", "ct")
OURS = ("init", "shop", "staging", "ct", "console")   # lo que se construye con el Dockerfile de la demo


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load((DEMO_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def services(compose) -> dict:
    return compose["services"]


def network_names(service: dict) -> set[str]:
    networks = service.get("networks", [])
    return set(networks) if isinstance(networks, (list, dict)) else set()


def environment(service: dict) -> dict:
    env = service.get("environment", {})
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    return {key: str(value) for key, value in env.items()}


# -- red y puertos -----------------------------------------------------------------------------------------------------------

def test_only_the_console_publishes_a_port_and_only_on_this_computer(services):
    published = {name: svc["ports"] for name, svc in services.items() if svc.get("ports")}
    assert list(published) == ["console"]
    (mapping,) = published["console"]
    assert str(mapping).startswith("127.0.0.1:"), mapping   # nunca 0.0.0.0: nadie de la red local entra
    assert str(mapping).endswith(":8080")
    assert not any("expose" in svc for svc in services.values())


def test_the_lab_network_has_no_way_out(compose, services):
    assert compose["networks"]["lab"]["internal"] is True
    assert not compose["networks"]["edge"].get("internal")
    for name in ("engine", "postgres", *PRACTICE):
        assert network_names(services[name]) == {"lab"}, name   # motor, base y sitios de práctica: solo la red sin salida
    assert network_names(services["console"]) == {"lab", "edge"}   # la consola necesita 'edge' únicamente para publicar su puerto
    assert services["init"]["network_mode"] == "none" and "networks" not in services["init"]


def test_nothing_is_privileged_or_shares_the_host(services):
    for name, svc in services.items():
        assert not svc.get("privileged"), name
        assert svc.get("network_mode") in (None, "none"), name
        assert svc.get("pid") is None and svc.get("ipc") is None and not svc.get("devices"), name
        for volume in svc.get("volumes", []):
            assert "docker.sock" not in str(volume) and not str(volume).startswith(("/", ".", "~")), (name, volume)   # solo volúmenes con nombre
        assert not svc.get("cap_add") or name == "init", name


def test_private_targets_are_allowed_only_in_the_engine(services):
    for name, svc in services.items():
        flag = environment(svc).get("ALLOW_PRIVATE_TARGETS")
        assert (flag == "true") == (name == "engine"), name


def test_the_engine_only_trusts_the_demo_authority_and_never_uses_a_proxy(services):
    env = environment(services["engine"])
    assert env["SSL_CERT_FILE"] == "/run/demo/pki/ca.pem"
    assert env["NO_PROXY"] == "*" and env["no_proxy"] == "*"
    assert env["CORS_ORIGINS"] == "[]" and env["DEBUG"] == "false" and env["TRUSTED_PROXY_COUNT"] == "0"


def test_the_practice_sites_answer_to_the_names_the_engine_looks_up(services):
    aliases = {name: services[name]["networks"]["lab"]["aliases"] for name in PRACTICE}
    assert aliases == {"shop": [ROLE_HOSTS["shop"]], "staging": [ROLE_HOSTS["staging"]], "ct": [ROLE_HOSTS["ct"]]}
    assert ROLE_HOSTS["shop"] == DOMAIN and ROLE_HOSTS["ct"] == "crt.sh"
    for name in PRACTICE:
        assert environment(services[name]) == {"PRACTICE_ROLE": name}
        assert services[name]["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": 0}   # abrir el 443 sin ser root


# -- secretos ----------------------------------------------------------------------------------------------------------------

def test_no_credential_is_written_in_the_compose_file(services):
    sensitive = re.compile(r"PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|DATABASE_URL", re.I)
    for name, svc in services.items():
        for key, value in environment(svc).items():
            if sensitive.search(key):
                assert key.endswith("_FILE") and value.startswith("/run/demo/"), (name, key)   # solo se indica el archivo donde está
    assert environment(services["postgres"])["POSTGRES_PASSWORD_FILE"] == "/run/demo/postgres_password"
    command = "\n".join(services["engine"]["command"])
    assert "$$(cat /run/demo/jwt_secret)" in command and "$$(cat /run/demo/postgres_password)" in command   # leídos al arrancar


def test_the_whole_demo_folder_has_no_hardcoded_secrets():
    pattern = re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]")
    skipped = {"tests", "__pycache__"}
    for path in DEMO_DIR.rglob("*"):
        if path.is_file() and not skipped & set(path.relative_to(DEMO_DIR).parts) and path.suffix in {".py", ".yml", ".js", ".html", ".md", ".txt"}:
            assert not pattern.search(path.read_text(encoding="utf-8")), path


def test_volumes_are_read_only_where_they_can_be(services):
    state, shared = "demo_state:/run/demo", "demo_shared:/run/shared"
    for name in ("postgres", "engine", *PRACTICE, "console"):
        assert f"{state}:ro" in services[name]["volumes"], name    # solo `init` escribe las credenciales y los certificados
    for name in PRACTICE:
        assert f"{shared}:ro" in services[name]["volumes"], name   # los sitios de práctica solo leen el archivo de verificación
    assert shared in services["console"]["volumes"]               # la consola es la única que lo escribe
    assert set(services["init"]["volumes"]) == {state, shared}


# -- endurecimiento ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", [*OURS, "engine"])
def test_containers_drop_every_capability_and_cannot_gain_more(services, name):
    svc = services[name]
    assert svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]


@pytest.mark.parametrize("name", OURS)
def test_our_containers_have_a_read_only_filesystem(services, name):
    assert services[name]["read_only"] is True


def test_only_init_adds_capabilities_and_only_the_three_it_needs(services):
    added = {name: svc["cap_add"] for name, svc in services.items() if svc.get("cap_add")}
    assert added == {"init": ["CHOWN", "DAC_OVERRIDE", "FOWNER"]}
    assert services["init"]["user"] == "root"
    others_root = [name for name, svc in services.items() if svc.get("user") == "root"]
    assert others_root == ["init"]


def test_the_database_lives_in_memory(services):
    assert services["postgres"]["tmpfs"] == ["/var/lib/postgresql/data"]
    assert not [v for v in services["postgres"]["volumes"] if "postgresql/data" in v]


# -- arranque ordenado ----------------------------------------------------------------------------------------------------------

def test_everything_waits_for_init_and_the_console_waits_for_the_engine(services):
    for name in ("postgres", "engine", *PRACTICE):
        assert services[name]["depends_on"]["init"]["condition"] == "service_completed_successfully", name
    assert services["engine"]["depends_on"]["postgres"]["condition"] == "service_healthy"
    console = services["console"]["depends_on"]
    assert console["engine"]["condition"] == "service_healthy"
    assert set(console) == {"engine", *PRACTICE}
    for name in ("postgres", "engine", "console"):
        assert "healthcheck" in services[name], name


def test_the_engine_is_built_from_the_unmodified_project_folder(services):
    assert services["engine"]["build"] == {"context": "../apps/engine"}
    assert "command" in services["engine"] and "alembic upgrade head" in "\n".join(services["engine"]["command"])


# -- imagen ----------------------------------------------------------------------------------------------------------------------

def test_dockerfile_runs_as_an_unprivileged_user_and_pins_its_dependency():
    dockerfile = (DEMO_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^USER demo$", dockerfile, re.M) and re.search(r"^FROM python:3\.\d+-slim$", dockerfile, re.M)
    assert "uid" not in dockerfile.lower() or "10002" in dockerfile
    requirements = [line for line in (DEMO_DIR / "requirements.txt").read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    assert requirements and all("==" in line for line in requirements)   # versión exacta: la demo siempre arma lo mismo


def test_every_file_the_image_copies_exists():
    dockerfile = (DEMO_DIR / "Dockerfile").read_text(encoding="utf-8")
    for source in re.findall(r"^COPY\s+(?!--)(.+?)\s+\S+$", dockerfile, re.M):
        for item in source.split():
            assert (DEMO_DIR / item).exists(), item
