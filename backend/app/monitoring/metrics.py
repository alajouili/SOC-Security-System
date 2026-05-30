"""
Prometheus Metrics — Observabilité du système SOC.
Métriques clés : latence, anomalies, alertes haute sévérité, authentification.
"""

from prometheus_client import Counter, Gauge, Histogram

# ── Histogramme : Latence des analyses (en ms) ────────────────────────────────
ANALYZE_LATENCY = Histogram(
    "soc_analyze_latency_ms",
    "Latence de l'analyse d'une entrée de log (ms)",
    buckets=[10, 25, 50, 100, 150, 200, 300, 500],
)

# ── Compteur : Nombre d'anomalies détectées ──────────────────────────────────
ANOMALY_RATE = Counter(
    "soc_anomaly_total",
    "Nombre total d'anomalies détectées",
)

# ── Compteur : Alertes haute sévérité ──────────────────────────────────────────
HIGH_RISK_COUNT = Counter(
    "soc_high_risk_total",
    "Nombre total d'alertes HIGH créées",
)

# ── Compteur : Tentatives de connexion échouées ─────────────────────────────────
AUTH_FAILURES = Counter(
    "soc_auth_failures_total",
    "Nombre total d'authentifications échouées",
    labelnames=["reason"],
)

# ── Gauge : Intégrité du modèle ────────────────────────────────────────────────
MODEL_INTEGRITY = Gauge(
    "soc_model_integrity",
    "État de vérification d'intégrité du modèle (1=OK, 0=FAILED)",
)

# ── Compteur : Injections détectées ──────────────────────────────────────────
THREATS_DETECTED = Counter(
    "soc_threats_detected_total",
    "Nombre total de menaces détectées",
    labelnames=["type"],  # sql_injection, xss, path_traversal, ssrf
)

# ── Gauge : Connexions WebSocket actives ────────────────────────────────────────
ACTIVE_WEBSOCKETS = Gauge(
    "soc_websocket_connections_active",
    "Nombre actuel de connexions WebSocket",
)
