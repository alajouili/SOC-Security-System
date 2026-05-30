"""
Tests unitaires — input_sanitizer.py
Vérifie la détection SQLi, XSS, Path Traversal avec encodages multiples.
"""

import pytest
from app.security.input_sanitizer import sanitize_string, sanitize_log_entry


class TestSQLInjectionDetection:
    def test_detects_union_select(self):
        r = sanitize_string("UNION SELECT username, password FROM users--")
        assert r.has_sqli is True
        assert "sql_injection" in r.threats_detected

    def test_detects_or_tautology(self):
        r = sanitize_string("' OR '1'='1")
        assert r.has_sqli is True

    def test_detects_sleep_function(self):
        r = sanitize_string("1' AND SLEEP(5)--")
        assert r.has_sqli is True

    def test_detects_url_encoded_sqli(self):
        r = sanitize_string("%27%20OR%20%271%27%3D%271")
        assert r.has_sqli is True

    def test_detects_sql_comments(self):
        r = sanitize_string("admin'--")
        assert r.has_sqli is True

    def test_detects_information_schema(self):
        r = sanitize_string("SELECT * FROM information_schema.tables")
        assert r.has_sqli is True

    def test_clean_string_no_sqli(self):
        r = sanitize_string("/api/users/profile")
        assert r.has_sqli is False

    def test_normal_endpoint_clean(self):
        r = sanitize_string("/home")
        assert not r.is_malicious


class TestXSSDetection:
    def test_detects_script_tag(self):
        r = sanitize_string("<script>alert('XSS')</script>")
        assert r.has_xss is True
        assert "xss" in r.threats_detected

    def test_detects_onerror(self):
        r = sanitize_string("<img src=x onerror=alert(1)>")
        assert r.has_xss is True

    def test_detects_javascript_uri(self):
        r = sanitize_string("javascript:alert(document.cookie)")
        assert r.has_xss is True

    def test_detects_url_encoded_xss(self):
        r = sanitize_string("%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        assert r.has_xss is True

    def test_detects_html_entity_encoded(self):
        # &#60; = < en entité HTML décimale — doit être détecté via le pattern combiné
        r = sanitize_string("&#60;script&#62;alert(1)&#60;/script&#62;")
        assert r.has_xss is True

    def test_detects_iframe(self):
        r = sanitize_string('<iframe src="javascript:alert(1)">')
        assert r.has_xss is True

    def test_clean_ua_no_xss(self):
        r = sanitize_string("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0")
        assert r.has_xss is False


class TestPathTraversalDetection:
    def test_detects_dotdot_slash(self):
        r = sanitize_string("../../../etc/passwd")
        assert r.has_path_traversal is True

    def test_detects_url_encoded_traversal(self):
        r = sanitize_string("%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        assert r.has_path_traversal is True

    def test_detects_etc_passwd_direct(self):
        r = sanitize_string("/etc/passwd")
        assert r.has_path_traversal is True

    def test_detects_double_encoded(self):
        r = sanitize_string("%252e%252e%252f")
        assert r.has_path_traversal is True

    def test_detects_windows_path(self):
        r = sanitize_string("..\\..\\windows\\system32")
        assert r.has_path_traversal is True

    def test_normal_path_clean(self):
        r = sanitize_string("/api/users/123")
        assert r.has_path_traversal is False


class TestSanitizeLogEntry:
    def _entry(self, **kwargs):
        base = {
            "ip": "10.0.0.1",
            "endpoint": "/home",
            "method": "GET",
            "status_code": 200,
            "requests_per_minute": 10.0,
            "response_time": 100.0,
            "user_agent": "Mozilla/5.0",
            "timestamp": "2026-01-01T10:00:00+00:00",
        }
        base.update(kwargs)
        return base

    def test_clean_entry_no_threats(self):
        _, threats = sanitize_log_entry(self._entry())
        assert threats == []

    def test_sqli_in_endpoint_detected(self):
        _, threats = sanitize_log_entry(self._entry(endpoint="/?id=1 UNION SELECT null--"))
        assert "sql_injection" in threats

    def test_xss_in_user_agent_detected(self):
        _, threats = sanitize_log_entry(self._entry(user_agent="<script>alert(1)</script>"))
        assert "xss" in threats

    def test_multiple_threats_detected(self):
        _, threats = sanitize_log_entry(self._entry(
            endpoint="/?id=1 UNION SELECT null--",
            user_agent="<script>alert(1)</script>",
        ))
        assert "sql_injection" in threats
        assert "xss" in threats

    def test_returns_unique_threats(self):
        _, threats = sanitize_log_entry(self._entry(
            endpoint="/?id=1 OR '1'='1",
        ))
        assert len(threats) == len(set(threats))