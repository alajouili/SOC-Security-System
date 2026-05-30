"""
Conftest pytest — fixtures partagées entre tous les tests.
"""

import pytest


@pytest.fixture
def sample_log_entry() -> dict:
    """Entrée de log normale standard pour les tests."""
    return {
        "ip": "192.168.1.10",
        "endpoint": "/api/items",
        "method": "GET",
        "status_code": 200,
        "requests_per_minute": 15.0,
        "response_time": 120.0,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "timestamp": "2026-01-01T10:00:00+00:00",
        "label": "normal",
    }


@pytest.fixture
def attack_log_entry() -> dict:
    """Entrée de log simulant une attaque SQLi + brute force."""
    return {
        "ip": "185.220.101.42",
        "endpoint": "/login?user=admin'--",
        "method": "POST",
        "status_code": 401,
        "requests_per_minute": 250.0,
        "response_time": 35.0,
        "user_agent": "sqlmap/1.7.8#stable",
        "timestamp": "2026-01-01T03:00:00+00:00",
        "label": "critical",
    }