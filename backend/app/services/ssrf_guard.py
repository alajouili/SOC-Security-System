"""
SSRF Guard — Protection SSRF — OWASP A10.
Bloque les plages IP privées RFC 1918, loopback et métadonnées cloud.
Les URLs dans les logs sont traitées comme données, jamais résolues.
"""

import ipaddress
import re
from urllib.parse import urlparse

import structlog

log = structlog.get_logger(__name__)

# ── Plages IP bloquées ───────────────────────────────────────────────────────

_BLOCKED_NETWORKS = [
    # RFC 1918 — Privées
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Link-local (métadonnées cloud AWS/GCP/Azure)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # Non-routables
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
]

# Patterns textuels pour détecter les IPs cloud dans les logs
_METADATA_PATTERNS = [
    re.compile(r"169\.254\.169\.254"),  # AWS/GCP/Azure metadata
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"169\.254\.170\.2"),  # ECS task metadata
]


def is_ip_blocked(ip_str: str) -> bool:
    """
    Vérifie si une adresse IP est dans une plage bloquée.

    Args:
        ip_str: Adresse IP sous forme de chaîne.

    Returns:
        True si l'IP est bloquée, False sinon.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for network in _BLOCKED_NETWORKS:
            if ip_obj in network:
                log.warning(
                    "ssrf_ip_blocked",
                    ip=ip_str,
                    matched_network=str(network),
                )
                return True
        return False
    except ValueError:
        # IP invalide — considérée comme non bloquée (gérer en amont)
        return False


def contains_ssrf_patterns(value: str) -> bool:
    """
    Détecte les patterns SSRF dans une chaîne de texte.
    Utilisé pour analyser les endpoints et user_agents des logs.

    Args:
        value: Chaîne à analyser.

    Returns:
        True si un pattern SSRF est détecté.
    """
    for pattern in _METADATA_PATTERNS:
        if pattern.search(value):
            log.warning("ssrf_pattern_detected", value_truncated=value[:100])
            return True

    # Tentative d'extraction et vérification d'IP dans l'URL
    try:
        parsed = urlparse(value)
        if parsed.hostname:
            try:
                return is_ip_blocked(parsed.hostname)
            except ValueError:
                pass
    except Exception:  # noqa: BLE001
        pass

    return False


def validate_log_entry_for_ssrf(entry_data: dict) -> list[str]:
    """
    Vérifie qu'un LogEntry ne contient pas de patterns SSRF.
    Les URLs ne sont JAMAIS résolues — données traitées comme texte uniquement.

    Args:
        entry_data: Dictionnaire des données du log.

    Returns:
        Liste des champs présentant un risque SSRF.
    """
    suspicious_fields: list[str] = []

    # Vérification de l'IP source
    ip_str = str(entry_data.get("ip", ""))
    if ip_str and contains_ssrf_patterns(ip_str):
        suspicious_fields.append("ip")

    # Vérification de l'endpoint (peut contenir une URL encodée)
    endpoint = str(entry_data.get("endpoint", ""))
    if endpoint and contains_ssrf_patterns(endpoint):
        suspicious_fields.append("endpoint")

    # Vérification du user_agent
    user_agent = str(entry_data.get("user_agent", ""))
    if user_agent and contains_ssrf_patterns(user_agent):
        suspicious_fields.append("user_agent")

    return suspicious_fields