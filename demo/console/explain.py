"""Textos de la consola: pasan los hallazgos del motor (técnicos, en inglés) a lenguaje de cliente.

El motor no cambia: estas explicaciones viven solo en la demo. Cada hallazgo conserva sus datos técnicos originales (la consola los
muestra en un desplegable), para que quien quiera ver "qué dijo exactamente el motor" lo vea.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {"critical": "crítico", "high": "alto", "medium": "medio", "low": "bajo", "info": "informativo"}
SEVERITY_PLURALS = {
    "critical": ("crítico", "críticos"), "high": ("alto", "altos"), "medium": ("medio", "medios"),
    "low": ("bajo", "bajos"), "info": ("informativo", "informativos"),
}

# cabecera -> (cómo se llama para un cliente, qué pasa si falta)
HEADERS = {
    "content-security-policy": (
        "política de contenido",
        "Sin esta cabecera el navegador no limita qué código puede cargar la página: si un atacante logra meter un script ajeno, "
        "se ejecuta con total libertad (ataque conocido como XSS).",
    ),
    "x-frame-options": (
        "protección contra incrustación",
        "Sin ella, otra web puede mostrar esta página dentro de un marco invisible y engañar a quien hace clic (clickjacking).",
    ),
    "strict-transport-security": (
        "obligación de usar HTTPS",
        "Sin ella, el navegador puede aceptar una conexión sin cifrar, y alguien en la misma red podría leer o alterar lo que viaja.",
    ),
}

CLOSE_OR_RESTRICT = "Cerrar el puerto en el firewall o limitarlo a las direcciones que realmente lo necesitan."


def where_of(evidence: dict, host_names: dict[str, str]) -> str:
    """El sitio al que se refiere un hallazgo, con el nombre si la dirección corresponde a un subdominio conocido."""
    host: Optional[str] = evidence.get("host")
    if not host and evidence.get("url"):
        host = urlsplit(str(evidence["url"])).hostname
    if not host:
        return ""
    host = str(host)
    name = host_names.get(host)
    return f"{name} ({host})" if name else host


def explain(finding: dict, host_names: dict[str, str]) -> dict:
    """Devuelve el hallazgo listo para mostrar: título, dónde, qué significa y qué hacer, más los datos técnicos originales."""
    category = str(finding.get("category", ""))
    severity = str(finding.get("severity", "info"))
    raw_title = str(finding.get("title", ""))
    evidence = finding.get("evidence") or {}
    where = where_of(evidence, host_names)

    title, what, todo = raw_title, str(finding.get("description") or ""), ""

    if category == "exposed_port" and raw_title == "Database port exposed":
        title = "Una base de datos está accesible desde la red"
        what = (
            f"El puerto {evidence.get('port')} ({evidence.get('service') or 'base de datos'}) de {where} responde. "
            "Una base de datos debería ser alcanzable solo por los sistemas que la usan; abierta, cualquiera puede probar claves "
            "comunes o aprovechar fallas conocidas del programa."
        )
        todo = CLOSE_OR_RESTRICT
    elif category == "exposed_port" and raw_title == "SSH exposed":
        title = "El acceso remoto (SSH) está abierto a la red"
        what = (
            f"El puerto {evidence.get('port', 22)} de {where} acepta conexiones de administración remota. Es normal tenerlo, "
            "pero abierto a todo internet recibe intentos de ingreso automáticos las 24 horas."
        )
        todo = "Limitarlo a direcciones conocidas (o a una VPN) y entrar con llaves en lugar de contraseñas."
    elif category in ("expired_certificate", "insecure_tls"):
        expired = category == "expired_certificate"
        title = "El certificado de seguridad está vencido" if expired else "El certificado de seguridad no es válido"
        when = f" el {str(evidence.get('valid_to', ''))[:10]}" if expired and evidence.get("valid_to") else ""
        what = (
            f"El certificado de {where}{' venció' + when if expired else ' no pasó la validación (vencido, de otro nombre o emitido por una entidad desconocida)'}. "
            "Los navegadores muestran una advertencia de «sitio no seguro» y la conexión no es de fiar."
        )
        todo = "Renovar el certificado o, si el servidor ya no se usa, apagarlo."
    elif category == "missing_security_header":
        header = str(evidence.get("missing_header", ""))
        label, consequence = HEADERS.get(header, (header, "El navegador no aplica esa protección."))
        title = f"Falta la {label}" if label != header else f"Falta la cabecera {header}"
        what = f"La respuesta de {where} no incluye la cabecera «{header}». {consequence}"
        todo = f"Agregar la cabecera «{header}» en la configuración del servidor web."
    elif category == "information_disclosure":
        title = "El servidor anuncia su versión exacta"
        what = (
            f"La respuesta de {where} dice «{evidence.get('server_header', '')}». Con ese dato, quien ataca busca directamente "
            "las fallas conocidas de esa versión."
        )
        todo = "Ocultar el número de versión en la configuración del servidor y mantenerlo actualizado."

    return {
        "severity": severity,
        "severity_label": SEVERITY_LABELS.get(severity, severity),
        "category": category,
        "title": title,
        "where": where,
        "what": what,
        "todo": todo,
        "raw_title": raw_title,
        "evidence": evidence,
    }


def readable_banner(banner: object) -> Optional[str]:
    """El saludo de un servicio tal como lo leyó el motor, sin la basura de un protocolo binario (MySQL, por ejemplo, empieza con
    bytes de control): lo que no se puede leer se resume en «…». El texto original sigue en el informe JSON."""
    if not isinstance(banner, str) or not banner.strip():
        return None
    text = banner.replace("\ufffd", ".")
    text = "".join(ch if ch.isprintable() else "." for ch in text)
    text = re.sub(r"\.{3,}", "…", text)
    return re.sub(r"\s{2,}", " ", text).strip()[:100] or None


def summary_line(counts: dict[str, int]) -> str:
    """'2 altos, 1 medio, 5 bajos'"""
    parts = []
    for severity in SEVERITY_ORDER:
        n = int(counts.get(severity, 0))
        if n:
            singular, plural = SEVERITY_PLURALS[severity]
            parts.append(f"{n} {singular if n == 1 else plural}")
    return ", ".join(parts) if parts else "sin hallazgos"


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        if severity in counts:
            counts[severity] += 1
    return counts
