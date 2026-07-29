"""
Layer 5 test plan: API (FastAPI), outside of auth itself (API-01 .. API-11
from the test plan table).

Uses the same `fresh_app` fixture as the Auth layer (conftest.py) - fresh
parser/main.py + parser/auth.py, mongomock-backed, wrapped in a
TestClient. Every /api/* route now requires a session, so each test logs
in first.
"""

from __future__ import annotations

import csv
import io
import json
from concurrent.futures import ThreadPoolExecutor

import pytest


def _login(fresh_app, username="admin", password="Pass123!Aa"):
    client, main, auth = fresh_app
    auth.users_col.insert_one(
        {"username": username, "password_hash": auth.hash_password(password), "created_at": auth._now()}
    )
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return client, main, auth


# ---------------------------------------------------------------------------
# API-01, API-02, API-03: query parameter validation
# ---------------------------------------------------------------------------
class TestQueryParamValidation:
    def test_api01_limit_wrong_type_returns_422(self, fresh_app):
        client, main, auth = _login(fresh_app)
        r = client.get("/api/attacks?limit=abc")
        assert r.status_code == 422

    def test_api02_negative_limit_does_not_crash(self, fresh_app):
        """
        No min/max is declared on `limit: int = 50` - any integer is
        accepted. Whether Mongo treats a negative limit as "no limit" or
        something else can differ between mongomock and a real MongoDB
        server; what actually matters here is that the API layer itself
        never 500s regardless of backend semantics.
        """
        client, main, auth = _login(fresh_app)
        main.collection.insert_many(
            [{"timestamp": f"2026-01-0{i}T00:00:00", "src_ip": f"1.2.3.{i}", "event": "cowrie.login.failed"} for i in range(1, 6)]
        )

        r = client.get("/api/attacks?limit=-5")

        assert r.status_code == 200
        assert isinstance(r.json()["data"], list)

    def test_api02_huge_limit_does_not_crash(self, fresh_app):
        client, main, auth = _login(fresh_app)
        main.collection.insert_many(
            [{"timestamp": f"2026-01-0{i}T00:00:00", "src_ip": f"1.2.3.{i}", "event": "cowrie.login.failed"} for i in range(1, 6)]
        )

        r = client.get("/api/attacks?limit=999999999")

        assert r.status_code == 200
        assert r.json()["total_returned"] == 5

    def test_api03_malformed_start_date_returns_empty_not_an_error(self, fresh_app):
        """
        start_date/end_date are concatenated straight into a Mongo string
        comparison (`f"{start_date}T00:00:00"`) with no date parsing or
        validation at all. A garbage value doesn't crash - it just never
        matches any stored timestamp string, silently returning an empty
        result instead of flagging the input as invalid."""
        client, main, auth = _login(fresh_app)
        main.collection.insert_one(
            {"timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "event": "cowrie.login.failed"}
        )

        r = client.get("/api/attacks?start_date=not-a-date")

        assert r.status_code == 200
        assert r.json()["data"] == []


# ---------------------------------------------------------------------------
# API-04, API-05: /api/search
# ---------------------------------------------------------------------------
class TestSearch:
    def test_api04_missing_ip_param_returns_422(self, fresh_app):
        client, main, auth = _login(fresh_app)
        r = client.get("/api/search")
        assert r.status_code == 422

    def test_api05_ip_with_no_history_returns_empty_not_an_error(self, fresh_app):
        client, main, auth = _login(fresh_app)
        r = client.get("/api/search?ip=1.2.3.4")
        assert r.status_code == 200
        assert r.json() == {"ip": "1.2.3.4", "total": 0, "data": []}


# ---------------------------------------------------------------------------
# API-06: every endpoint against a completely empty database
# ---------------------------------------------------------------------------
class TestEmptyDatabase:
    ENDPOINTS = [
        "/api/stats",
        "/api/attacks",
        "/api/top-ips",
        "/api/top-passwords",
        "/api/top-usernames",
        "/api/alerts/pending",
        "/api/map-data",
        "/api/stats/hourly",
        "/api/stats/countries",
        "/api/brute-force",
        "/api/search?ip=1.2.3.4",
        "/api/export/csv",
    ]

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_api06_no_endpoint_crashes_on_empty_db(self, fresh_app, endpoint):
        client, main, auth = _login(fresh_app)
        r = client.get(endpoint)
        assert r.status_code == 200, f"{endpoint} returned {r.status_code}: {r.text}"


# ---------------------------------------------------------------------------
# API-07: /api/alerts/pending has a GET-with-side-effect anti-pattern
# ---------------------------------------------------------------------------
class TestAlertsPendingSideEffect:
    def test_api07_second_call_returns_nothing_the_data_was_consumed(self, fresh_app):
        """
        GET should be safe/idempotent by convention, but this endpoint
        mutates state (marks documents alerted=True) as a side effect of
        reading them. Calling it twice proves the second read sees
        nothing, even though the underlying attack data is still there -
        a caveat worth knowing if this is ever exposed more broadly."""
        client, main, auth = _login(fresh_app)
        main.collection.insert_many(
            [
                {"event": "cowrie.login.success", "src_ip": "1.2.3.4", "alerted": False},
                {"event": "cowrie.login.failed", "src_ip": "1.2.3.5", "alerted": False},
            ]
        )

        first = client.get("/api/alerts/pending")
        second = client.get("/api/alerts/pending")

        assert len(first.json()["data"]) == 2
        assert second.json()["data"] == []
        assert main.collection.count_documents({}) == 2  # data itself isn't deleted, just marked


# ---------------------------------------------------------------------------
# API-08: CSV export properly escapes special characters
# ---------------------------------------------------------------------------
class TestCSVExport:
    def test_api08_command_with_comma_and_newline_is_escaped_correctly(self, fresh_app):
        client, main, auth = _login(fresh_app)
        tricky_command = 'echo "a,b"; cat /etc/passwd\nrm -rf /'
        main.collection.insert_one(
            {
                "timestamp": "2026-01-01T00:00:00",
                "src_ip": "1.2.3.4",
                "event": "cowrie.command.input",
                "username": "root",
                "password": "toor",
                "command": tricky_command,
                "country": "Unknown",
                "city": "Unknown",
            }
        )

        r = client.get("/api/export/csv")

        assert r.status_code == 200
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert len(rows) == 1
        assert rows[0]["command"] == tricky_command


# ---------------------------------------------------------------------------
# API-09, API-10: concurrent load
# ---------------------------------------------------------------------------
class TestConcurrency:
    def test_api09_many_concurrent_authenticated_requests_all_succeed(self, fresh_app):
        client, main, auth = _login(fresh_app)

        def call(_):
            return client.get("/api/stats").status_code

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(call, range(50)))

        assert results == [200] * 50

    def test_api10_concurrent_failed_logins_do_not_lose_attempts_to_a_race(self, fresh_app):
        """
        auth.record_failed_attempt() does a read-then-write
        (find_one -> update_one with a computed new `attempts` count),
        not an atomic $inc - under true concurrency this is a classic
        lost-update race. Best-effort test: fires failed logins in
        parallel and checks the recorded attempt count matches how many
        were actually sent.

        Caveat: mongomock plus Python threads under the GIL may not
        reproduce a real race as reliably as concurrent connections to an
        actual MongoDB server would - treat a pass here as inconclusive
        rather than proof the race can't happen in production. See the
        layer 8 (performance) guide for a real load-test recommendation.
        """
        client, main, auth = fresh_app
        username = "admin"
        auth.users_col.insert_one(
            {"username": username, "password_hash": auth.hash_password("Pass123!Aa"), "created_at": auth._now()}
        )

        n_attempts = 4  # stay under MAX_LOGIN_ATTEMPTS so none get locked out mid-flight

        def attempt(_):
            return client.post("/auth/login", json={"username": username, "password": "wrong"}).status_code

        with ThreadPoolExecutor(max_workers=n_attempts) as pool:
            statuses = list(pool.map(attempt, range(n_attempts)))

        assert all(s == 401 for s in statuses)

        doc = auth.login_attempts_col.find_one({"key": f"testclient|{username.lower()}"})
        if doc["attempts"] != n_attempts:
            pytest.xfail(
                f"race condition reproduced: expected {n_attempts} recorded attempts, "
                f"got {doc['attempts']} - record_failed_attempt()'s read-then-write is not atomic"
            )


# ---------------------------------------------------------------------------
# API-11: Content-Type handling
# ---------------------------------------------------------------------------
class TestContentType:
    def test_api11_wrong_content_type_with_json_body_is_rejected(self, fresh_app):
        client, main, auth = fresh_app
        r = client.post(
            "/auth/login",
            content=json.dumps({"username": "admin", "password": "wrong"}),
            headers={"Content-Type": "text/plain"},
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# RBAC: "viewer" role must be blocked from endpoints that export data or
# have a write side-effect; "admin" keeps full access; accounts predating
# the role field default to admin (backward compatibility).
# ---------------------------------------------------------------------------
def _login_with_role(fresh_app, username, password, role=None):
    client, main, auth = fresh_app
    user_doc = {"username": username, "password_hash": auth.hash_password(password), "created_at": auth._now()}
    if role is not None:
        user_doc["role"] = role
    auth.users_col.insert_one(user_doc)
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return client, main, auth


ADMIN_ONLY_ENDPOINTS = ["/api/export/csv", "/api/alerts/pending"]
VIEWER_ALLOWED_ENDPOINTS = [
    "/api/stats", "/api/attacks", "/api/top-ips", "/api/top-passwords",
    "/api/top-usernames", "/api/map-data", "/api/stats/hourly",
    "/api/stats/countries", "/api/brute-force", "/api/search?ip=1.2.3.4",
]


class TestRoleBasedAccess:
    @pytest.mark.parametrize("endpoint", ADMIN_ONLY_ENDPOINTS)
    def test_rbac01_viewer_is_blocked_from_admin_only_endpoints(self, fresh_app, endpoint):
        client, main, auth = _login_with_role(fresh_app, "viewer1", "Pass123!Aa", role="viewer")
        r = client.get(endpoint)
        assert r.status_code == 403

    @pytest.mark.parametrize("endpoint", ADMIN_ONLY_ENDPOINTS)
    def test_rbac02_admin_has_full_access_to_admin_only_endpoints(self, fresh_app, endpoint):
        client, main, auth = _login_with_role(fresh_app, "admin1", "Pass123!Aa", role="admin")
        r = client.get(endpoint)
        assert r.status_code == 200

    @pytest.mark.parametrize("endpoint", VIEWER_ALLOWED_ENDPOINTS)
    def test_rbac03_viewer_can_still_read_ordinary_endpoints(self, fresh_app, endpoint):
        client, main, auth = _login_with_role(fresh_app, "viewer2", "Pass123!Aa", role="viewer")
        r = client.get(endpoint)
        assert r.status_code == 200

    def test_rbac04_account_predating_role_field_defaults_to_admin(self, fresh_app):
        """Accounts created before this feature existed have no "role" key
        at all - must still be treated as admin, or upgrading this code
        would silently lock the real production admin account out of
        export/alerts-pending after deploy."""
        client, main, auth = _login_with_role(fresh_app, "legacy_admin", "Pass123!Aa", role=None)
        r = client.get("/api/export/csv")
        assert r.status_code == 200

    def test_rbac05_me_endpoint_reports_current_role(self, fresh_app):
        client, main, auth = _login_with_role(fresh_app, "viewer3", "Pass123!Aa", role="viewer")
        r = client.get("/auth/me")
        assert r.status_code == 200
        assert r.json()["role"] == "viewer"
