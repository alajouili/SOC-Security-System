import json
import random
from datetime import datetime, timedelta, timezone

random.seed(42)

NORMAL_IPS = [f"10.0.{random.randint(1,50)}.{random.randint(1,254)}" for _ in range(30)]

ATTACKER_IPS = [
    "192.168.100.5",
    "185.220.101.42",
    "45.33.32.156"
]

NORMAL_ENDPOINTS = [
    "/",
    "/home",
    "/products",
    "/api/items"
]

ATTACK_ENDPOINTS = [
    "/admin",
    "/login",
    "/etc/passwd"
]

NORMAL_UAS = [
    "Mozilla/5.0 Chrome/120"
]

ATTACK_UAS = [
    "sqlmap/1.7.8",
    "curl/7.88.1"
]

base_time = datetime.now(timezone.utc)

logs = []

# Logs normaux
for i in range(425):

    ts = base_time + timedelta(minutes=i)

    logs.append({
        "ip": random.choice(NORMAL_IPS),
        "endpoint": random.choice(NORMAL_ENDPOINTS),
        "method": "GET",
        "status_code": 200,
        "requests_per_minute": round(random.uniform(1, 40), 2),
        "response_time": round(random.uniform(20, 400), 2),
        "user_agent": random.choice(NORMAL_UAS),
        "timestamp": ts.isoformat(),
        "label": "normal"
    })

# Logs suspects
for i in range(50):

    ts = base_time + timedelta(minutes=i)

    logs.append({
        "ip": random.choice(ATTACKER_IPS),
        "endpoint": "/login",
        "method": "POST",
        "status_code": 401,
        "requests_per_minute": round(random.uniform(60, 90), 2),
        "response_time": round(random.uniform(100, 900), 2),
        "user_agent": random.choice(ATTACK_UAS),
        "timestamp": ts.isoformat(),
        "label": "suspect"
    })

# Logs critiques
for i in range(25):

    ts = base_time + timedelta(minutes=i)

    logs.append({
        "ip": random.choice(ATTACKER_IPS),
        "endpoint": random.choice(ATTACK_ENDPOINTS),
        "method": "POST",
        "status_code": 500,
        "requests_per_minute": round(random.uniform(100, 5000), 2),
        "response_time": round(random.uniform(1, 50), 2),
        "user_agent": random.choice(ATTACK_UAS),
        "timestamp": ts.isoformat(),
        "label": "critical"
    })

with open("logs.json", "w") as f:
    json.dump(logs, f, indent=2)

print("Dataset généré avec succès")