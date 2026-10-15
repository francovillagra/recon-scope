"""La guarda que impide usar el motor para mirar redes internas (SSRF). No necesita base de datos."""
import ipaddress
import socket
import sys

import pytest

from app.config import settings
from app.recon.netguard import BlockedTarget, connect_any, is_public_ip, resolve_public

from .netfakes import LocalServer, fake_dns

PUBLIC = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "2606:4700:4700::1111",
    "2a00:1450:4001:81b::200e",
    "::ffff:8.8.8.8",  # IPv4 público escrito como IPv6
    "64:ff9b::808:808",  # NAT64 de 8.8.8.8
]

NON_PUBLIC = [
    # IPv4
    "127.0.0.1", "127.255.255.254", "0.0.0.0", "0.1.2.3",
    "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1",
    "169.254.169.254",  # metadatos de AWS/GCP/Azure
    "169.254.0.1",
    "100.64.0.1", "100.100.100.200",  # CGNAT, incluye los metadatos de Alibaba
    "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
    "224.0.0.1", "239.255.255.250",  # multicast
    "240.0.0.1", "255.255.255.255",
    # IPv6
    "::1", "::", "fe80::1", "fe80::a00:27ff:fe4e:66a1", "fc00::1", "fd00::1", "fd12:3456:789a::1", "fec0::1",
    "ff02::1", "ff05::2",
    "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254", "::ffff:0.0.0.0",  # IPv4 interno dentro de IPv6
    "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",  # NAT64 de 127.0.0.1 y de 169.254.169.254
    "64:ff9b:1::1",
    "2002:7f00:1::", "2002:808:808::",  # 6to4: no hay motivo legítimo para conectarse
    "2001::1", "2001:db8::1", "100::1",
    "::7f00:1",  # IPv4-compatible (obsoleto)
]


@pytest.mark.parametrize("text", PUBLIC)
def test_public_addresses_are_allowed(text):
    assert is_public_ip(ipaddress.ip_address(text)) is True


@pytest.mark.parametrize("text", NON_PUBLIC)
def test_internal_and_special_addresses_are_blocked(text):
    assert is_public_ip(ipaddress.ip_address(text)) is False


async def test_literal_public_address_needs_no_dns():
    assert await resolve_public("8.8.8.8", 80, allow_private=False) == ["8.8.8.8"]


@pytest.mark.skipif(sys.platform != "linux", reason="depende de cómo interpreta getaddrinfo las formas raras de IPv4")
@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "[::1]", "::1", "0.0.0.0", "169.254.169.254", "2130706433", "0x7f.0.0.1", "127.1", "0177.0.0.1"],
)
async def test_loopback_is_blocked_however_it_is_spelled(host):
    """Se juzga la dirección ya resuelta, no el texto: 2130706433 y 0x7f.1 también son 127.0.0.1."""
    with pytest.raises(BlockedTarget):
        await resolve_public(host, 80, allow_private=False)


async def test_a_name_pointing_to_an_internal_address_is_blocked(monkeypatch):
    fake_dns(monkeypatch, {"evil.test": ["10.0.0.5"]})
    with pytest.raises(BlockedTarget) as blocked:
        await resolve_public("evil.test", 443, allow_private=False)
    assert blocked.value.host == "evil.test"
    assert blocked.value.reason == "non_public_address"


async def test_a_mixed_answer_is_blocked_even_when_the_first_address_is_public(monkeypatch):
    fake_dns(monkeypatch, {"mixed.test": ["93.184.216.34", "127.0.0.1"]})
    with pytest.raises(BlockedTarget):
        await resolve_public("mixed.test", 80, allow_private=False)
    fake_dns(monkeypatch, {"mixed.test": ["2606:4700:4700::1111", "fd00::1"]})
    with pytest.raises(BlockedTarget):
        await resolve_public("mixed.test", 80, allow_private=False)


async def test_ipv4_goes_first_and_duplicates_are_removed(monkeypatch):
    fake_dns(monkeypatch, {"dual.test": ["2606:4700:4700::1111", "1.1.1.1", "1.1.1.1"]})
    assert await resolve_public("dual.test", 443, allow_private=False) == ["1.1.1.1", "2606:4700:4700::1111"]


async def test_a_name_that_does_not_resolve_is_an_os_error_not_a_block(monkeypatch):
    fake_dns(monkeypatch, {})
    with pytest.raises(socket.gaierror):
        await resolve_public("nope.test", 80, allow_private=False)


async def test_the_setting_is_read_on_every_call(monkeypatch):
    fake_dns(monkeypatch, {"lab.test": ["127.0.0.1"]})
    with pytest.raises(BlockedTarget):
        await resolve_public("lab.test", 80)  # por defecto, bloqueado
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    assert await resolve_public("lab.test", 80) == ["127.0.0.1"]
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", False)
    with pytest.raises(BlockedTarget):
        await resolve_public("lab.test", 80)


def test_private_targets_are_off_by_default():
    assert settings.ALLOW_PRIVATE_TARGETS is False


async def test_connect_any_falls_back_to_the_next_address():
    async with LocalServer() as server:
        # 127.0.0.2 no escucha en ese puerto (el servidor está en 127.0.0.1): la primera falla y se prueba la segunda
        reader, writer = await connect_any(["127.0.0.2", "127.0.0.1"], server.port, timeout=2)
        writer.close()
        await writer.wait_closed()
        assert server.connections == 1


async def test_connect_any_reports_the_last_error_when_nothing_answers():
    async with LocalServer() as server:
        port = server.port
    with pytest.raises(OSError):
        await connect_any(["127.0.0.1"], port, timeout=2)  # el servidor ya se cerró
