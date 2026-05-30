"""
Input Sanitizer — OWASP A03.
Sanitization des entrées avant le pipeline ML.
Détection SQL Injection, XSS, Path Traversal avec encodages multiples (URL, hex, base64).
"""

import base64
import re
import urllib.parse
from dataclasses import dataclass, field

import structlog

log = structlog.get_logger(__name__)


# ── Patterns de détection ────────────────────────────────────────────────────

# SQL Injection — standard + encodages
_SQLI_PATTERNS: list[re.Pattern] = [
    # Syntaxe directe
    re.compile(r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b)", re.IGNORECASE),
    re.compile(r"(?i)(\binsert\b.*\binto\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b)", re.IGNORECASE),
    re.compile(r"(?i)(\bexec\b|\bexecute\b|\bxp_\w+|\bsp_\w+)", re.IGNORECASE),
    re.compile(r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", re.IGNORECASE),
    re.compile(r"(?i)(information_schema|sys\.tables|sysobjects|pg_catalog)", re.IGNORECASE),
    # Commentaires SQL
    re.compile(r"(--|#|/\*.*?\*/)", re.DOTALL),
    # Apostrophe + logique
    re.compile(r"'.*?(or|and)\s+['\"0-9]", re.IGNORECASE),
    re.compile(r"(?i)(\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
]

# XSS — standard + obfusqué
_XSS_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)<script[\s\S]*?>[\s\S]*?</script>"),
    re.compile(r"(?i)<script[\s\S]*?/?>"),
    re.compile(r"(?i)javascript\s*:", re.IGNORECASE),
    re.compile(r"(?i)on\w+\s*=\s*[\"']?\s*\w+", re.IGNORECASE),  # onclick=, onerror=…
    re.compile(r"(?i)<iframe[\s\S]*?>"),
    re.compile(r"(?i)<img[^>]+src\s*=\s*[\"']?\s*javascript:", re.IGNORECASE),
    re.compile(r"(?i)expression\s*\(", re.IGNORECASE),
    re.compile(r"(?i)vbscript\s*:", re.IGNORECASE),
    re.compile(r"(?i)data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"&#x[0-9a-f]+;", re.IGNORECASE),   # Encodage HTML hex
    re.compile(r"&#\d+;.*script", re.IGNORECASE),  # Encodage HTML décimal + script
    re.compile(r"\\u[0-9a-f]{4}", re.IGNORECASE),  # Encodage unicode
]

# Path Traversal
_PATH_TRAVERSAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"%2e%2e/", re.IGNORECASE),
    re.compile(r"\.\.%2f", re.IGNORECASE),
    re.compile(r"%252e%252e", re.IGNORECASE),  # Double encodage
    re.compile(r"(?i)(etc/passwd|etc/shadow|windows/system32|boot\.ini)", re.IGNORECASE),
]


@dataclass
class SanitizationResult:
    """Résultat de la sanitization d'une entrée."""

    original: str
    sanitized: str
    threats_detected: list[str] = field(default_factory=list)
    has_sqli: bool = False
    has_xss: bool = False
    has_path_traversal: bool = False

    @property
    def is_malicious(self) -> bool:
        return bool(self.threats_detected)


def _decode_variants(value: str) -> list[str]:
    """
    Produit toutes les variantes décodées d'une chaîne pour détecter
    les attaques obfusquées (URL, double URL, hex, base64).
    """
    variants = [value]

    # Décodage URL simple
    try:
        decoded_url = urllib.parse.unquote(value)
        if decoded_url != value:
            variants.append(decoded_url)
    except Exception:  # noqa: BLE001
        pass

    # Double décodage URL
    try:
        double_decoded = urllib.parse.unquote(urllib.parse.unquote(value))
        if double_decoded not in variants:
            variants.append(double_decoded)
    except Exception:  # noqa: BLE001
        pass

    # Tentative de décodage base64 (si la chaîne ressemble à du base64)
    if len(value) % 4 == 0 and re.match(r"^[A-Za-z0-9+/=]+$", value):
        try:
            b64_decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
            if b64_decoded and b64_decoded not in variants:
                variants.append(b64_decoded)
        except Exception:  # noqa: BLE001
            pass

    return variants


def sanitize_string(value: str, field_name: str = "input") -> SanitizationResult:
    """
    Sanitize une chaîne de caractères.
    Détecte SQLi, XSS et Path Traversal sur toutes les variantes encodées.

    Args:
        value: La chaîne à analyser.
        field_name: Nom du champ (pour les logs).

    Returns:
        SanitizationResult avec les menaces détectées.
    """
    if not value:
        return SanitizationResult(original=value, sanitized=value)

    # Limitation de longueur défensive
    value = value[:4096]

    result = SanitizationResult(original=value, sanitized=value)
    variants = _decode_variants(value)

    # ── Détection SQL Injection ───────────────────────────────────────────
    for variant in variants:
        for pattern in _SQLI_PATTERNS:
            if pattern.search(variant):
                result.has_sqli = True
                result.threats_detected.append("sql_injection")
                break
        if result.has_sqli:
            break

    # ── Détection XSS ────────────────────────────────────────────────────
    for variant in variants:
        for pattern in _XSS_PATTERNS:
            if pattern.search(variant):
                result.has_xss = True
                result.threats_detected.append("xss")
                break
        if result.has_xss:
            break

    # ── Détection Path Traversal ──────────────────────────────────────────
    for variant in variants:
        for pattern in _PATH_TRAVERSAL_PATTERNS:
            if pattern.search(variant):
                result.has_path_traversal = True
                result.threats_detected.append("path_traversal")
                break
        if result.has_path_traversal:
            break

    if result.threats_detected:
        log.warning(
            "threats_detected",
            field=field_name,
            threats=result.threats_detected,
            value_truncated=value[:100],
        )

    return result


def sanitize_log_entry(entry_data: dict) -> tuple[dict, list[str]]:
    """
    Sanitize tous les champs string d'un LogEntry.
    Retourne le dictionnaire nettoyé et la liste des menaces détectées.

    Args:
        entry_data: Dictionnaire des données du log (post-validation Pydantic).

    Returns:
        Tuple (données sanitisées, liste des menaces).
    """
    string_fields = ["endpoint", "user_agent"]
    all_threats: list[str] = []
    sanitized = dict(entry_data)

    for field_name in string_fields:
        raw_value = entry_data.get(field_name, "")
        if not raw_value:
            continue

        result = sanitize_string(str(raw_value), field_name=field_name)
        all_threats.extend(result.threats_detected)
        # On conserve la valeur originale pour le log mais on marque les menaces

    return sanitized, list(set(all_threats))