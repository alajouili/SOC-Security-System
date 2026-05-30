#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# generate_keys.sh — Génération de la paire de clés RS256 (RSA 2048 bits)
# Usage : bash scripts/generate_keys.sh
# Les clés sont sauvegardées dans keys/ (exclu de git via .gitignore)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

KEYS_DIR="$(dirname "$0")/../keys"
mkdir -p "$KEYS_DIR"

echo "[SOC] Génération de la paire de clés RSA 2048 bits pour JWT RS256..."

# Clé privée
openssl genrsa -out "$KEYS_DIR/private.pem" 2048
echo "[SOC] ✓ Clé privée générée : keys/private.pem"

# Clé publique extraite
openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"
echo "[SOC] ✓ Clé publique générée : keys/public.pem"

# Mot de passe PostgreSQL (généré aléatoirement)
if [ ! -f "$KEYS_DIR/db_password.txt" ]; then
    openssl rand -base64 32 > "$KEYS_DIR/db_password.txt"
    echo "[SOC] ✓ Mot de passe PostgreSQL généré : keys/db_password.txt"
else
    echo "[SOC] ℹ  keys/db_password.txt existe déjà — conservé."
fi

# Permissions restrictives
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/public.pem"
chmod 600 "$KEYS_DIR/db_password.txt"

echo ""
echo "[SOC] ✓ Clés générées avec succès dans keys/"
echo "[SOC] ⚠  Ne jamais committer ce répertoire (vérifié par .gitignore)"
echo ""
echo "Empreinte de la clé publique :"
openssl rsa -in "$KEYS_DIR/private.pem" -pubout 2>/dev/null | openssl pkey -pubin -fingerprint -noout