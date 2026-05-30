# SOC Security System v2.0

> **Security Operations Center** — Détection d'anomalies intelligente, OWASP Top 10 2021, prêt pour la production.

```
Stack : FastAPI · scikit-learn · PostgreSQL · Docker · Prometheus
Auth  : JWT RS256 · bcrypt cost=12 · RBAC (admin/analyst/viewer)
ML    : Isolation Forest · Cross-validation temporelle · SHA-256 integrity
```

---

## Table des matières

1. [Architecture](#1-architecture)
2. [Installation pas à pas](#2-installation-pas-à-pas)
3. [Génération des clés RS256](#3-génération-des-clés-rs256)
4. [Configuration PostgreSQL](#4-configuration-postgresql)
5. [Lancement avec Docker Compose](#5-lancement-avec-docker-compose)
6. [Entraînement du modèle](#6-entraînement-du-modèle)
7. [API REST — Endpoints et exemples curl](#7-api-rest--endpoints-et-exemples-curl)
8. [WebSocket temps réel](#8-websocket-temps-réel)
9. [Contrôles OWASP Top 10 2021](#9-contrôles-owasp-top-10-2021)
10. [Observabilité & Métriques Prometheus](#10-observabilité--métriques-prometheus)
11. [Guide de calibration des poids de scoring](#11-guide-de-calibration-des-poids-de-scoring)
12. [Modélisation des menaces](#12-modélisation-des-menaces)
13. [Tests unitaires](#13-tests-unitaires)
14. [Audit des dépendances](#14-audit-des-dépendances)

---

## 1. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser / API)                       │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ HTTPS
┌───────────────────────────────▼─────────────────────────────────────┐
│                      FastAPI (port 8000)                             │
│                                                                      │
│  Middlewares (ordre d'exécution) :                                   │
│  1. AuditLoggerMiddleware   → audit_logs (append-only)               │
│  2. SecurityHeadersMiddleware → CSP, HSTS, X-Frame-Options           │
│  3. SlowAPIMiddleware       → rate limiting par IP                   │
│  4. CORSMiddleware          → whitelist explicite                    │
│                                                                      │
│  Routes :                                                            │
│  POST /auth/register   POST /auth/login   POST /auth/refresh         │
│  POST /analyze         GET  /logs         GET  /alerts               │
│  GET  /stats           WS   /ws           GET  /health               │
└──────┬──────────────────────┬──────────────────────┬────────────────┘
       │                      │                      │
┌──────▼──────┐    ┌──────────▼──────────┐  ┌───────▼────────────────┐
│  PostgreSQL │    │   Pipeline ML        │  │  Prometheus            │
│  (port 5432)│    │                      │  │  (port 9090)           │
│             │    │  1. input_sanitizer  │  │                        │
│  users      │    │  2. ssrf_guard       │  │  soc_analyze_latency   │
│  logs       │    │  3. preprocessing    │  │  soc_anomaly_total     │
│  alerts     │    │  4. anomaly_detect   │  │  soc_high_risk_total   │
│  audit_logs │    │  5. scoring (0-100)  │  │  soc_auth_failures     │
│             │    │  6. alerts_engine    │  │  soc_model_integrity   │
└─────────────┘    └──────────────────────┘  └────────────────────────┘
```

### Arborescence des fichiers

```
backend/
├── app/
│   ├── main.py                     # FastAPI factory, middlewares, CORS strict
│   ├── middleware/
│   │   ├── rate_limiter.py         # slowapi — limiter partagé
│   │   ├── security_headers.py     # CSP, HSTS, X-Frame-Options, Permissions-Policy
│   │   └── audit_logger.py         # Toutes les requêtes → audit_logs
│   ├── routes/
│   │   ├── auth.py                 # Register / Login / Refresh
│   │   ├── analyze.py              # POST /analyze — cœur du pipeline
│   │   ├── logs.py                 # GET /logs — paginé, filtré
│   │   ├── alerts.py               # GET /alerts + /stats + PATCH acknowledge
│   │   └── websocket.py            # WS /ws — rooms par rôle
│   ├── services/
│   │   ├── preprocessing.py        # Feature extraction — identique train/infer
│   │   ├── anomaly_detection.py    # Isolation Forest + vérif. intégrité SHA-256
│   │   ├── scoring.py              # Risk score 0–100, signaux pondérés
│   │   ├── alerts_engine.py        # Création alertes + dispatch WebSocket
│   │   ├── training.py             # Entraînement + CV temporelle + manifeste
│   │   ├── jwt_handler.py          # RS256 create/verify/refresh
│   │   └── ssrf_guard.py           # Blocage RFC 1918, loopback, cloud metadata
│   ├── database/
│   │   ├── database.py             # Engine asyncpg + TLS + session factory
│   │   └── models.py               # ORM — users, logs, alerts, audit_logs
│   ├── schemas/
│   │   ├── user_schema.py          # Pydantic v2 — email, password complexity
│   │   ├── log_schema.py           # LogEntry + contraintes strictes
│   │   └── alert_schema.py         # AlertOut + pagination
│   ├── security/
│   │   ├── permissions.py          # RBAC — décorateurs FastAPI
│   │   ├── input_sanitizer.py      # SQLi, XSS, Path Traversal + multi-encodages
│   │   └── sbom.py                 # Inventaire dépendances + CVE check
│   ├── monitoring/
│   │   └── metrics.py              # Définitions Prometheus
│   └── model/
│       ├── anomaly_model.pkl       # Généré par training.py (signé SHA-256)
│       └── model_manifest.json     # Hash + version + métriques
├── monitoring/
│   ├── prometheus.yml              # Config scraping
│   └── alerts_rules.yml            # Règles Prometheus (latence, anomalies, BF)
├── data/
│   ├── logs.json                   # Dataset synthétique 500 entrées
│   └── attack_samples.json         # Corpus attaques labellisées (70+ samples)
├── keys/                           # ⚠ Gitignored — jamais committer
│   ├── private.pem
│   ├── public.pem
│   └── db_password.txt
├── scripts/
│   ├── generate_keys.sh            # Génération paire RSA 2048
│   └── train_model.sh              # Lancement entraînement
├── tests/
│   ├── conftest.py
│   ├── test_scoring.py
│   ├── test_anomaly_detection.py
│   └── test_input_sanitizer.py
├── alembic/                        # Migrations versionnées
├── Dockerfile                      # Multi-stage, user non-root, read-only FS
├── docker-compose.yml              # 3 services + Docker secrets + TLS
├── requirements.txt
├── requirements-audit.txt
├── alembic.ini
└── .env.example
```

---

## 2. Installation pas à pas

### Prérequis

| Outil | Version minimum |
|-------|----------------|
| Docker | 26+ |
| Docker Compose | 2.27+ |
| Python (dev local) | 3.12+ |
| OpenSSL | 3.0+ |

### Clonage et préparation

```bash
git clone <repo-url> soc-system
cd soc-system/backend

# Copier le fichier d'environnement
cp .env.example .env
# ⚠ Ne jamais mettre de vraies valeurs dans .env.example
```

### Installation locale (développement uniquement)

```bash
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

pip install -r requirements.txt
pip install -r requirements-audit.txt
pip install pytest pytest-asyncio  # Tests
```

---

## 3. Génération des clés RS256

> **Obligatoire avant tout démarrage.** Les clés ne sont jamais dans le dépôt git.

```bash
# Génère keys/private.pem, keys/public.pem, keys/db_password.txt
bash scripts/generate_keys.sh
```

Vérification :

```bash
ls -la keys/
# -rw------- private.pem   (600)
# -rw-r--r-- public.pem    (644)
# -rw------- db_password.txt (600)

# Test de la clé
openssl rsa -in keys/private.pem -check -noout
# RSA key ok
```

En production, stocker les clés dans un gestionnaire de secrets (Vault, AWS Secrets Manager) et les injecter via Docker secrets — jamais via variables d'environnement en clair.

---

## 4. Configuration PostgreSQL

La connexion utilise TLS obligatoire (`sslmode=require`) en production.

```bash
# Vérifier le contenu du mot de passe généré
cat keys/db_password.txt

# Test de connexion (après lancement Docker)
docker exec -it soc-db-1 psql -U socuser -d socdb -c "\dt"
```

### Variables d'environnement importantes

```env
DATABASE_URL=postgresql+asyncpg://socuser@db:5432/socdb
JWT_ALGORITHM=RS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
BCRYPT_ROUNDS=12
ENVIRONMENT=production          # 'development' pour activer Swagger
CONTAMINATION_RATE=0.03
```

---

## 5. Lancement avec Docker Compose

```bash
# 1. Générer les clés (si pas déjà fait)
bash scripts/generate_keys.sh

# 2. Construire et démarrer les 3 services
docker compose up --build -d

# 3. Vérifier l'état des services
docker compose ps
docker compose logs backend --follow

# 4. Vérifier le healthcheck
curl http://localhost:8000/health
# {"status":"ok","version":"2.0.0"}
```

### Lancer les migrations Alembic

```bash
# Dans le conteneur backend
docker compose exec backend alembic upgrade head

# Ou localement (avec DATABASE_URL pointant vers le bon hôte)
alembic upgrade head
```

### Arrêt

```bash
docker compose down           # Arrêt sans suppression des volumes
docker compose down -v        # Suppression des volumes (reset complet)
```

---

## 6. Entraînement du modèle

Le modèle doit être entraîné **avant** le premier appel à `/analyze`.

```bash
# Dans le conteneur
docker compose exec backend bash scripts/train_model.sh

# En local (avec .venv actif)
bash scripts/train_model.sh data/logs.json

# Directement en Python
python -m app.services.training data/logs.json
```

**Sortie attendue :**
```json
{
  "cv_anomaly_rates": [0.028, 0.031, 0.029, 0.033, 0.027],
  "cv_mean": 0.0296,
  "cv_std": 0.002,
  "total_samples": 500,
  "n_normal": 485,
  "n_suspect": 15,
  "n_critical": 3,
  "contamination": 0.03,
  "precision": 0.87,
  "recall": 0.91,
  "f1_score": 0.89
}
```

Le modèle est sauvegardé dans `app/model/anomaly_model.pkl` avec son hash SHA-256 dans `model_manifest.json`. Toute modification non autorisée du fichier `.pkl` est détectée au prochain chargement.

**Ré-entraînement hebdomadaire recommandé** (crontab) :
```bash
0 2 * * 0  docker compose exec -T backend bash scripts/train_model.sh
```

---

## 7. API REST — Endpoints et exemples curl

### Authentification

#### Créer un compte

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }'
```

**Réponse :**
```json
{
  "id": 1,
  "username": "alice",
  "email": "alice@example.com",
  "role": "admin",
  "is_active": true,
  "last_login": null,
  "created_at": "2026-01-01T10:00:00Z"
}
```

#### Se connecter

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }'
```

**Réponse :**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

```bash
# Stocker le token pour les requêtes suivantes
export TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Renouveler le token

```bash
curl -X POST http://localhost:8000/auth/refresh \
  -b "refresh_token=<token_httponly>"
```

---

### Analyse de log

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.42",
    "endpoint": "/login",
    "method": "POST",
    "status_code": 401,
    "requests_per_minute": 250,
    "response_time": 45,
    "user_agent": "sqlmap/1.7.8#stable",
    "timestamp": "2026-01-15T14:32:11Z"
  }'
```

**Réponse :**
```json
{
  "log_id": 42,
  "risk_score": 87.5,
  "risk_level": "HIGH",
  "is_anomaly": true,
  "techniques": ["sql_injection", "brute_force", "rate_abuse"],
  "owasp_ref": "A03:2021",
  "score_breakdown": {
    "requests_per_minute": 20.0,
    "http_error": 20.0,
    "sensitive_endpoint": 15.0,
    "isolation_forest": 16.5,
    "sql_injection": 10.0,
    "xss": 0.0,
    "brute_force": 5.0,
    "path_traversal_ssrf": 0.0
  },
  "feature_importance": {
    "requests_per_minute": 0.42,
    "status_code": 0.28,
    "endpoint_risk": 0.18,
    "response_time": 0.07,
    "method_encoded": 0.03,
    "is_sensitive_endpoint": 0.01,
    "hour_of_day": 0.01
  },
  "inference_time_ms": 12.4,
  "total_latency_ms": 45.2,
  "alert_id": 7
}
```

---

### Consulter les logs

```bash
# Tous les logs (paginés)
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/logs?page=1&page_size=20"

# Filtrer par IP et anomalies uniquement
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/logs?ip=192.168.1.42&anomaly_only=true"

# Filtrer par plage de dates et score minimum
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/logs?date_from=2026-01-01T00:00:00Z&min_score=50"
```

---

### Alertes

```bash
# Toutes les alertes HIGH non acquittées
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/alerts?level=HIGH&acknowledged=false"

# Acquitter une alerte (analyst/admin uniquement)
curl -X PATCH http://localhost:8000/alerts/7/acknowledge \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"acknowledged": true}'

# Statistiques agrégées
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/stats"
```

**Réponse /stats :**
```json
{
  "total_analyzed": 1250,
  "total_alerts": 87,
  "high_count": 12,
  "medium_count": 45,
  "low_count": 30,
  "avg_risk_score": 23.4,
  "top_ips": [
    {"ip": "185.220.101.42", "count": 145},
    {"ip": "45.33.32.156", "count": 89}
  ],
  "top_endpoints": [
    {"endpoint": "/login", "count": 320},
    {"endpoint": "/api/users", "count": 187}
  ],
  "anomaly_rate": 6.96
}
```

---

## 8. WebSocket temps réel

Connexion au flux d'alertes en temps réel :

```bash
# wscat (npm install -g wscat)
wscat -c "ws://localhost:8000/ws?token=$TOKEN"
```

```javascript
// JavaScript / Browser
const ws = new WebSocket(`ws://localhost:8000/ws?token=${accessToken}`);

ws.onopen = () => console.log('Connecté au SOC');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.type === 'ALERT') {
    console.log(`🚨 [${data.level}] ${data.message}`);
    console.log(`Score: ${data.score} | OWASP: ${data.owasp_ref}`);
    console.log(`Techniques: ${data.techniques.join(', ')}`);
  }
};

// Ping keepalive
ws.send(JSON.stringify({ type: 'ping' }));
```

**Format des messages reçus :**

```json
{
  "type": "ALERT",
  "level": "HIGH",
  "message": "SQL Injection détectée sur /api/users depuis 185.220.101.42",
  "score": 94.0,
  "ip": "185.220.101.42",
  "endpoint": "/api/users",
  "techniques": ["sql_injection", "error_based"],
  "owasp_ref": "A03:2021",
  "timestamp": "2026-01-15T14:32:11Z",
  "alert_id": 42
}
```

**Rooms par rôle :**

| Rôle | Niveaux reçus |
|------|--------------|
| `viewer` | LOW, MEDIUM |
| `analyst` | LOW, MEDIUM, HIGH |
| `admin` | LOW, MEDIUM, HIGH |

---

## 9. Contrôles OWASP Top 10 2021

| ID | Contrôle | Implémentation |
|----|----------|----------------|
| **A01** | Broken Access Control | RBAC dans `permissions.py` · Object-level authorization · WS rooms par rôle |
| **A02** | Cryptographic Failures | JWT RS256 2048 bits · bcrypt cost=12 · TLS PostgreSQL · Docker secrets |
| **A03** | Injection | ORM SQLAlchemy paramétré · `input_sanitizer.py` · Regex multi-encodages |
| **A04** | Insecure Design | Threat model documenté · Least privilege · Erreurs API génériques |
| **A05** | Security Misconfiguration | CSP/HSTS/X-Frame-Options · CORS whitelist · Swagger off en prod · Debug off |
| **A06** | Vulnerable Components | `pip-audit` + `safety` en CI/CD · SBOM généré · Versions min. fixées |
| **A07** | Auth Failures | Rate limit /login · Verrouillage après 5 échecs · Messages non différenciés |
| **A08** | Data Integrity | SHA-256 sur `anomaly_model.pkl` · Vérification à chaque chargement |
| **A09** | Logging & Monitoring | `audit_logs` append-only (trigger PG) · Logs JSON structurés · Prometheus |
| **A10** | SSRF | `ssrf_guard.py` · RFC 1918 bloqué · Métadonnées cloud bloquées |

---

## 10. Observabilité & Métriques Prometheus

Accès : `http://localhost:9090`

| Métrique | Type | Seuil d'alerte |
|----------|------|----------------|
| `soc_analyze_latency_ms` | Histogram | p99 > 200ms → warning |
| `soc_anomaly_total` | Counter | Taux > 15% sur 5min → critical |
| `soc_high_risk_total` | Counter | > 10/min → critical |
| `soc_auth_failures_total` | Counter | > 20/min par IP → brute force |
| `soc_model_integrity` | Gauge | 0 = hash mismatch → critical |
| `soc_ws_connections` | Gauge | Suivi par rôle |

Exemples de requêtes PromQL :

```promql
# Latence p99 sur 5 minutes
histogram_quantile(0.99, rate(soc_analyze_latency_ms_bucket[5m]))

# Taux d'anomalies (%)
rate(soc_anomaly_total[5m]) / rate(soc_analyze_latency_ms_count[5m]) * 100

# Détection brute force par IP (top 5)
topk(5, rate(soc_auth_failures_total[5m]))
```

---

## 11. Guide de calibration des poids de scoring

> ⚠ Les poids actuels sont des hypothèses initiales. **Calibrer après 30 jours de données réelles.**

### Méthodologie de calibration

**Étape 1 — Collecte des données de référence (J1 à J30)**

```sql
-- Extraire les logs avec leur score et les alertes confirmées
SELECT l.risk_score, l.anomaly, a.level, a.techniques
FROM logs l
LEFT JOIN alerts a ON a.log_id = l.id
WHERE l.created_at > NOW() - INTERVAL '30 days';
```

**Étape 2 — Analyse des faux positifs**

```sql
-- Alertes acquittées (faux positifs probables)
SELECT score, techniques, COUNT(*) as count
FROM alerts
WHERE acknowledged = true
GROUP BY score, techniques
ORDER BY count DESC;
```

**Étape 3 — Ajustement des poids dans `scoring.py`**

Les poids à ajuster se trouvent dans `compute_risk_score()` :

```python
# Exemple : si trop de faux positifs sur RPM élevé mais trafic légitime
# Réduire le poids RPM de 20 → 12 pour les CDN

# Signal RPM (actuel : +20 max)
if signals.has_critical_rpm:
    rpm_score = 20.0   # ← Ajuster ici
elif signals.has_high_rpm:
    rpm_score = 10.0   # ← Et ici

# Augmenter le seuil RPM critique si beaucoup de pics légitimes
_RPM_CRITICAL = 100.0  # ← Ajuster selon le trafic réel
```

**Étape 4 — Validation croisée**

Ré-entraîner le modèle avec les données des 30 jours et vérifier que le F1 score s'améliore.

**Cibles de performance :**
- Faux positifs ≤ 5% (MEDIUM+)
- Rappel ≥ 85% sur les attaques confirmées
- Précision ≥ 80%

---

## 12. Modélisation des menaces

### Acteurs de menace identifiés

| Acteur | Capacité | Vecteurs principaux |
|--------|----------|---------------------|
| Script kiddie | Faible | Scanners automatisés (Nikto, sqlmap) |
| Attaquant ciblé | Moyenne | SQLi manuel, brute force slow |
| APT | Élevée | SSRF, supply chain, zero-day |
| Insider malveillant | Élevée | Accès direct DB, exfiltration |

### Surfaces d'attaque et mitigations

```
┌──────────────────┬─────────────────────────────┬──────────────────────────┐
│ Surface          │ Menace                      │ Mitigation               │
├──────────────────┼─────────────────────────────┼──────────────────────────┤
│ /auth/login      │ Brute force, stuffing        │ Rate limit + lockout     │
│ /analyze         │ Injection via LogEntry       │ Sanitizer + Pydantic     │
│ WebSocket /ws    │ Token expired replay         │ Revalidation par message │
│ Modèle ML        │ Model poisoning              │ SHA-256 + manifeste      │
│ PostgreSQL       │ SQL Injection                │ ORM paramétré            │
│ Docker secrets   │ Leak clé privée              │ Mode 600, jamais en .env │
│ audit_logs       │ Falsification de piste       │ Trigger PG append-only   │
│ Prometheus /metrics│ Reconnaissance interne     │ Accès réseau restreint   │
└──────────────────┴─────────────────────────────┴──────────────────────────┘
```

### Flux de données sensibles

```
Mot de passe → bcrypt(cost=12) → hashed_password [DB]
                                                   ↑
                                     Jamais en clair, jamais dans les logs

JWT payload → RS256(private.pem) → token [client]
           ← RS256(public.pem)  ← vérification [backend]
                                                ↑
                                  Clé privée : Docker secret uniquement
```

### Hypothèses de sécurité

- Le réseau interne Docker est de confiance (pas de mTLS inter-services dans cette version)
- Les certificats TLS PostgreSQL sont gérés par l'infrastructure
- Les backups de base de données sont chiffrés (hors scope de cette spec)

---

## 13. Tests unitaires

```bash
# Lancer tous les tests
pytest tests/ -v

# Avec couverture
pytest tests/ -v --cov=app --cov-report=term-missing

# Tests unitaires uniquement (pas d'intégration)
pytest tests/test_scoring.py tests/test_anomaly_detection.py tests/test_input_sanitizer.py -v
```

**Couverture attendue :**

```
tests/test_scoring.py            ✓ 18 tests — Risk score, signaux, OWASP refs
tests/test_anomaly_detection.py  ✓ 20 tests — Preprocessing, normalisation, intégrité
tests/test_input_sanitizer.py    ✓ 17 tests — SQLi, XSS, Path Traversal, encodages
```

---

## 14. Audit des dépendances

```bash
# Scan CVE des dépendances installées
pip-audit --requirement requirements.txt

# Safety check
safety check -r requirements.txt

# Générer le SBOM complet
python -c "from app.security.sbom import save_sbom; save_sbom('/tmp/sbom.json')"
cat /tmp/sbom.json
```

Intégrer dans le pipeline CI/CD :

```yaml
# .github/workflows/security.yml (exemple)
- name: Audit dépendances
  run: |
    pip install -r requirements-audit.txt
    pip-audit --requirement requirements.txt --format json > audit-report.json
    safety check -r requirements.txt
```

---

## Licence

Usage interne — Confidentiel. Ne pas distribuer.