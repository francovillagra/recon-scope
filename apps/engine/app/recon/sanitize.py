"""
Limpieza de texto que viene de la red antes de guardarlo.

Los banners, títulos y cabeceras los controla el servidor escaneado. PostgreSQL no admite el byte NUL en
columnas de texto ni en JSONB (un MySQL, por ejemplo, saluda con bytes nulos), y el resto de los caracteres
de control no aporta nada en un informe.
"""
import re
from typing import Any, Optional

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return _CONTROL_CHARS.sub(".", value)


def clean_json(value: Any) -> Any:
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, dict):
        return {clean_text(str(k)): clean_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_json(v) for v in value]
    return value
