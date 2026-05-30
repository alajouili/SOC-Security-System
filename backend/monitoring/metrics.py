"""
Métriques Prometheus — Observabilité SOC.
Toutes les métriques définies ici, importées par les routes concernées.
"""

from prometheus_client import Counter, Gauge, Histogram

# ── Latence d'analyse ─────────────────────────────────────────────────────
ANALYZE_LATENCY = Histogram(
    "soc_analyze_latency_ms",
    "Latence de l'endpoint /analyze en millisecondes",
    buckets=[10, 25, 50, 100, 150, 200, 300, 500, 1000],
)

# ── Taux d'anomalies ──────────────────────────────────────────────────────
ANOMALY_RATE = Counter(
    "soc_anomaly_total",
    "Nombre total d'anomalies détectées",
)

# ── Alertes HIGH ──────────────────────────────────────────────────────────
HIGH_RISK_COUNT = Counter(
    "soc_high_risk_total",
    "Nombre total d'entrées de niveau HIGH",
)

# ── Échecs d'authentification ─────────────────────────────────────────────
AUTH_FAILURES = Counter(
    "soc_auth_failures_total",
    "Nombre total d'échecs d'authentification",
    labelnames=["ip"],
)

# ── Intégrité du modèle ───────────────────────────────────────────────────
MODEL_INTEGRITY = Gauge(
    "soc_model_integrity",
    "1 = modèle intègre, 0 = hash mismatch",
)
MODEL_INTEGRITY.set(1)  # Initialisation optimiste

# ── Connexions WebSocket actives ──────────────────────────────────────────
WS_CONNECTIONS = Gauge(
    "soc_ws_connections",
    "Nombre de connexions WebSocket actives",
    labelnames=["role"],
)