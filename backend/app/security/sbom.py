"""
SBOM — Software Bill of Materials — OWASP A06.
Génération de l'inventaire des dépendances et vérification CVE.
"""

import importlib.metadata
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)


def generate_sbom() -> dict:
    """
    Génère le SBOM complet des dépendances installées.

    Returns:
        Dictionnaire avec métadonnées et liste des packages.
    """
    packages = []

    for dist in importlib.metadata.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.metadata["Version"]
            packages.append({"name": name, "version": version})
        except Exception:  # noqa: BLE001
            continue

    sbom = {
        "generated_at": datetime.now(UTC).isoformat(),
        "total_packages": len(packages),
        "packages": sorted(packages, key=lambda x: x["name"].lower()),
    }

    return sbom


def run_pip_audit() -> dict:
    """
    Lance pip-audit pour détecter les vulnérabilités CVE.

    Returns:
        Résultats de l'audit avec liste des vulnérabilités.
    """
    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--progress-spinner", "off"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        audit_data = json.loads(result.stdout) if result.stdout else {}
        vulnerabilities = audit_data.get("vulnerabilities", [])

        if vulnerabilities:
            log.warning(
                "pip_audit_vulnerabilities_found",
                count=len(vulnerabilities),
                packages=[v.get("name") for v in vulnerabilities],
            )
        else:
            log.info("pip_audit_clean", message="Aucune vulnérabilité détectée")

        return {
            "status": "clean" if not vulnerabilities else "vulnerable",
            "vulnerabilities": vulnerabilities,
            "checked_at": datetime.now(UTC).isoformat(),
        }

    except FileNotFoundError:
        log.warning("pip_audit_not_installed")
        return {"status": "unavailable", "error": "pip-audit non installé"}
    except subprocess.TimeoutExpired:
        log.error("pip_audit_timeout")
        return {"status": "timeout", "error": "pip-audit a dépassé le délai"}
    except Exception as exc:  # noqa: BLE001
        log.error("pip_audit_error", error=str(exc))
        return {"status": "error", "error": str(exc)}


def save_sbom(output_path: str = "/tmp/sbom.json") -> Path:  # noqa: S108
    """
    Génère et sauvegarde le SBOM sur disque.

    Args:
        output_path: Chemin de sortie du fichier JSON.

    Returns:
        Path vers le fichier généré.
    """
    sbom = generate_sbom()
    path = Path(output_path)
    path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False))
    log.info("sbom_saved", path=str(path), packages=sbom["total_packages"])
    return path