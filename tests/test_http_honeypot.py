"""
Tests for parser/http_honeypot.py - the second honeypot service (a fake
HTTP admin login page), independent of the Cowrie SSH/Telnet side.

Goes through the `fresh_module` fixture (see conftest.py) so the module's
`client = MongoClient(...)` line runs against an isolated in-memory
mongomock instance, never the real "honeypot" database.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def http_honeypot(fresh_module):
    return fresh_module("http_honeypot")


@pytest.fixture
def client(http_honeypot):
    return TestClient(http_honeypot.app)


def _docs(http_honeypot):
    return list(http_honeypot.collection.find())


class TestRobotsTxt:
    def test_robots_txt_served(self, client):
        res = client.get("/robots.txt")
        assert res.status_code == 200
        assert "Disallow: /admin/" in res.text

    def test_robots_txt_not_logged(self, client, http_honeypot):
        client.get("/robots.txt")
        assert _docs(http_honeypot) == []


class TestLoginPageServing:
    @pytest.mark.parametrize(
        "path",
        ["admin/login.php", "admin", "admin/", "login", "wp-login.php"],
    )
    def test_known_bait_paths_serve_login_page(self, client, path):
        res = client.get(f"/{path}")
        assert res.status_code == 200
        assert "PaymentCo" in res.text
        assert "<form method=\"POST\">" in res.text

    def test_unknown_path_returns_404(self, client):
        res = client.get("/.env")
        assert res.status_code == 404
        assert res.text == "Not Found"

    def test_every_get_request_is_logged(self, client, http_honeypot):
        client.get("/admin/login.php")
        client.get("/some/random/scanner/path")
        docs = _docs(http_honeypot)
        assert len(docs) == 2
        assert all(d["event"] == "http.request" for d in docs)


class TestLoginAttemptCapture:
    def test_post_with_username_password_logs_login_attempt(self, client, http_honeypot):
        res = client.post("/admin/login.php", data={"username": "admin", "password": "hunter2"})
        assert res.status_code == 401
        assert "Invalid username or password" in res.text

        docs = _docs(http_honeypot)
        assert len(docs) == 1
        doc = docs[0]
        assert doc["event"] == "http.login.attempt"
        assert doc["username"] == "admin"
        assert doc["password"] == "hunter2"
        assert doc["mitre_techniques"] == ["T1110"]

    @pytest.mark.parametrize(
        "form,expected_user,expected_pass",
        [
            ({"user": "root", "pass": "toor"}, "root", "toor"),
            ({"email": "a@b.com", "passwd": "secret"}, "a@b.com", "secret"),
        ],
    )
    def test_alternate_field_names_are_recognized(self, client, http_honeypot, form, expected_user, expected_pass):
        client.post("/login", data=form)
        doc = _docs(http_honeypot)[0]
        assert doc["username"] == expected_user
        assert doc["password"] == expected_pass

    def test_post_without_credential_fields_falls_back_to_http_request(self, client, http_honeypot):
        res = client.post("/some/path", data={"foo": "bar"})
        assert res.status_code == 404
        doc = _docs(http_honeypot)[0]
        assert doc["event"] == "http.request"
        assert doc["mitre_techniques"] == []

    def test_username_only_is_still_captured(self, client, http_honeypot):
        client.post("/admin/login.php", data={"username": "admin"})
        doc = _docs(http_honeypot)[0]
        assert doc["event"] == "http.login.attempt"
        assert doc["username"] == "admin"
        assert doc["password"] is None


class TestLoggedDocumentSchema:
    def test_document_matches_attacks_collection_shape(self, client, http_honeypot):
        client.get("/admin/login.php")
        doc = _docs(http_honeypot)[0]

        assert doc["dst_port"] == 80
        assert doc["method"] == "GET"
        assert doc["path"] == "/admin/login.php"
        assert doc["command"] is None
        assert doc["session"] is None
        assert doc["alerted"] is False
        assert "created_at" in doc
        assert "timestamp" in doc
        assert doc["sensor"]

    def test_mongo_insert_failure_does_not_break_response(self, client, http_honeypot, monkeypatch):
        def _boom(*args, **kwargs):
            raise RuntimeError("mongo is down")

        monkeypatch.setattr(http_honeypot.collection, "insert_one", _boom)
        res = client.get("/admin/login.php")
        assert res.status_code == 200
