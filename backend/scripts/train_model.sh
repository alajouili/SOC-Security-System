#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# train_model.sh — Entraînement de l'Isolation Forest
# Usage : bash scripts/train_model.sh [chemin_dataset]
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

DATA_PATH="${1:-data/logs.json}"
MODEL_PATH="${MODEL_PATH:-app/model/anomaly_model.pkl}"

echo "[SOC] Démarrage de l'entraînement du modèle Isolation Forest..."
echo "[SOC] Dataset : $DATA_PATH"
echo "[SOC] Modèle  : $MODEL_PATH"
echo ""

# Lancement du module training
python -m app.services.training "$DATA_PATH"

echo ""
echo "[SOC] ✓ Entraînement terminé."
echo "[SOC] ✓ Modèle sauvegardé : $MODEL_PATH"
echo "[SOC] ✓ Manifeste SHA-256 : app/model/model_manifest.json"
echo ""
echo "Pour recharger le modèle en production sans redémarrer :"
echo "  POST /admin/reload-model  (admin uniquement)"