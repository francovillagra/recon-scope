"""
Lo que el motor NO hizo durante un escaneo y por qué.

Un destino omitido (porque apunta a una red interna), un tope alcanzado (máximo de hosts, de subdominios,
de tiempo) o un resultado parcial se informan como hallazgos informativos. Sin eso, quien escanea recibe un
informe vacío o incompleto sin saber que fue a propósito.
"""
from typing import Any


class ScanNotes:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str], dict[str, Any]] = {}
        self._hosts: set[str] = set()

    def skip_host(self, host: str, reason: str) -> None:
        """El motor no se conectó a `host`. Se registra una sola vez por (motivo, host)."""
        self._hosts.add(host)
        self._items.setdefault((reason, host), {"reason": reason, "host": host})

    def note(self, reason: str, **evidence: Any) -> None:
        """Un hecho del escaneo que no es de un host (tope alcanzado, resultado parcial). Una vez por motivo."""
        self._items.setdefault((reason, ""), {"reason": reason, **evidence})

    def is_skipped(self, host: str) -> bool:
        return host in self._hosts

    def items(self) -> list[dict[str, Any]]:
        return list(self._items.values())

    def __len__(self) -> int:
        return len(self._items)
