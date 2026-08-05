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
from prometheus_client.parser import text_string_to_metric_families


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
        "/api/auth-log",
        "/api/auth-log/verify",
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

    @pytest.mark.parametrize("payload", [
        "=cmd|'/c calc'!A1",
        "+1+1",
        "-2+3",
        "@SUM(1,1)",
    ])
    def test_api12_formula_payload_in_username_is_neutralized(self, fresh_app, payload):
        """OWASP CSV/Formula Injection: a cell starting with =, +, -, or @
        is evaluated as a formula by Excel/Sheets/LibreOffice when the
        exported file is opened. export_csv() must prefix any such value
        with a single quote so it's treated as plain text instead."""
        client, main, auth = _login(fresh_app)
        main.collection.insert_one(
            {
                "timestamp": "2026-01-01T00:00:00",
                "src_ip": "1.2.3.4",
                "event": "cowrie.login.failed",
                "username": payload,
                "password": "toor",
                "command": None,
                "country": "Unknown",
                "city": "Unknown",
            }
        )

        r = client.get("/api/export/csv")

        assert r.status_code == 200
        # The raw CSV text must never contain the payload at the start of
        # a field - only prefixed with a leading single quote.
        assert f",{payload}," not in r.text
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert rows[0]["username"] == "'" + payload


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
# Generic per-IP rate limit on every /api/* endpoint (auth.check_api_rate_limit)
# ---------------------------------------------------------------------------
class TestApiRateLimit:
    def test_api13_exceeding_the_limit_returns_429(self, fresh_app, monkeypatch):
        client, main, auth = _login(fresh_app)
        monkeypatch.setattr(auth, "API_RATE_LIMIT_MAX_REQUESTS", 3)

        statuses = [client.get("/api/stats").status_code for _ in range(4)]

        assert statuses == [200, 200, 200, 429]

    def test_api13_limit_is_shared_across_different_api_endpoints(self, fresh_app, monkeypatch):
        """The rate limit is per-IP (applied at the api_router level), not
        per-route - hammering one endpoint counts against the budget for
        all of them."""
        client, main, auth = _login(fresh_app)
        monkeypatch.setattr(auth, "API_RATE_LIMIT_MAX_REQUESTS", 2)

        assert client.get("/api/stats").status_code == 200
        assert client.get("/api/attacks").status_code == 200
        assert client.get("/api/top-ips").status_code == 429

    def test_api13_login_endpoint_is_not_subject_to_the_api_rate_limit(self, fresh_app, monkeypatch):
        """/auth/login isn't registered on api_router, so exhausting the
        generic API rate limit must not lock a user out of logging in -
        it has its own dedicated, stricter per-(ip,username) lockout
        (auth.check_rate_limit / TestBruteForceLockout)."""
        client, main, auth = fresh_app
        auth.users_col.insert_one(
            {"username": "admin", "password_hash": auth.hash_password("Pass123!Aa"), "created_at": auth._now()}
        )
        monkeypatch.setattr(auth, "API_RATE_LIMIT_MAX_REQUESTS", 0)

        r = client.post("/auth/login", json={"username": "admin", "password": "Pass123!Aa"})

        assert r.status_code == 200

    def test_api13_concurrent_requests_never_exceed_the_limit(self, fresh_app, monkeypatch):
        """check_api_rate_limit uses find_one_and_update's atomic $inc
        (unlike record_failed_attempt's read-then-write, which
        test_api10 above documents as racy) - under concurrency, no more
        than API_RATE_LIMIT_MAX_REQUESTS calls should ever succeed."""
        client, main, auth = _login(fresh_app)
        monkeypatch.setattr(auth, "API_RATE_LIMIT_MAX_REQUESTS", 10)

        def call(_):
            return client.get("/api/stats").status_code

        with ThreadPoolExecutor(max_workers=20) as pool:
            statuses = list(pool.map(call, range(20)))

        assert statuses.count(200) == 10
        assert statuses.count(429) == 10


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
# /metrics: Prometheus scrape endpoint (parser/metrics.py, parser/main.py)
# ---------------------------------------------------------------------------
def _metric_value(metrics_text, name, labels=None):
    labels = labels or {}
    for family in text_string_to_metric_families(metrics_text):
        for sample in family.samples:
            if sample.name == name and all(sample.labels.get(k) == v for k, v in labels.items()):
                return sample.value
    return None


class TestMetricsEndpoint:
    def test_metrics01_reachable_without_login(self, fresh_app):
        """Prometheus has no way to authenticate against this app's JWT/
        cookie flow, so /metrics must stay reachable with no session."""
        client, main, auth = fresh_app
        r = client.get("/metrics")
        assert r.status_code == 200

    def test_metrics02_not_subject_to_the_generic_api_rate_limit(self, fresh_app, monkeypatch):
        """/metrics is registered directly on `app`, not api_router, so it
        must never 429 regardless of how exhausted the /api/* rate limit
        budget is."""
        client, main, auth = fresh_app
        monkeypatch.setattr(auth, "API_RATE_LIMIT_MAX_REQUESTS", 0)

        statuses = [client.get("/metrics").status_code for _ in range(5)]

        assert statuses == [200] * 5

    def test_metrics03_includes_expected_metric_families(self, fresh_app):
        client, main, auth = fresh_app
        text = client.get("/metrics").text
        for expected in (
            "honeypot_http_requests_total",
            "honeypot_http_request_duration_seconds",
            "honeypot_login_attempts_total",
            "honeypot_api_rate_limit_rejections_total",
            "honeypot_attacks_total",
            "honeypot_attacks_by_event_total",
            "honeypot_pending_alerts",
        ):
            assert expected in text, f"{expected} missing from /metrics output"

    def test_metrics04_login_attempts_counter_increments_by_result(self, fresh_app):
        """Metric counters are process-wide singletons that persist across
        every test in the session (not reset per test), so this asserts
        the DELTA from one login of each kind, not an absolute value."""
        client, main, auth = fresh_app
        auth.users_col.insert_one(
            {"username": "admin", "password_hash": auth.hash_password("Pass123!Aa"), "created_at": auth._now()}
        )
        before = client.get("/metrics").text
        before_failed = _metric_value(before, "honeypot_login_attempts_total", {"result": "failed"}) or 0
        before_success = _metric_value(before, "honeypot_login_attempts_total", {"result": "success"}) or 0

        client.post("/auth/login", json={"username": "admin", "password": "wrong"})
        client.post("/auth/login", json={"username": "admin", "password": "Pass123!Aa"})

        after = client.get("/metrics").text
        assert _metric_value(after, "honeypot_login_attempts_total", {"result": "failed"}) == before_failed + 1
        assert _metric_value(after, "honeypot_login_attempts_total", {"result": "success"}) == before_success + 1

    def test_metrics05_pending_alerts_gauge_reflects_current_mongo_state(self, fresh_app):
        """Unlike the counters above, this is a Gauge computed live from
        Mongo at scrape time (see main.py's _MongoStatsCollector) - each
        fresh_app gets its own isolated mongomock database, so this can
        assert an exact value rather than a delta."""
        client, main, auth = fresh_app
        main.collection.insert_many(
            [
                {"event": "cowrie.login.failed", "alerted": False},
                {"event": "cowrie.login.failed", "alerted": False},
                {"event": "cowrie.login.success", "alerted": True},
            ]
        )

        text = client.get("/metrics").text

        assert _metric_value(text, "honeypot_pending_alerts") == 2


# ---------------------------------------------------------------------------
# /api/stats/mitre, /api/stats/heatmap
# ---------------------------------------------------------------------------
class TestMitreAndHeatmapStats:
    def test_mt01_mitre_stats_groups_and_names_techniques(self, fresh_app):
        client, main, auth = _login(fresh_app)
        main.collection.insert_many([
            {"mitre_techniques": ["T1110", "T1078"]},
            {"mitre_techniques": ["T1110"]},
            {"mitre_techniques": []},
            {"mitre_techniques": ["T9999"]},  # unknown ID - falls back to itself as name
        ])

        r = client.get("/api/stats/mitre")

        assert r.status_code == 200
        data = {d["technique"]: d for d in r.json()["data"]}
        assert data["T1110"]["count"] == 2
        assert data["T1110"]["name"] == "Brute Force"
        assert data["T1078"]["count"] == 1
        assert data["T9999"]["name"] == "T9999"

    def test_ht01_heatmap_returns_168_buckets_with_correct_counts(self, fresh_app):
        client, main, auth = _login(fresh_app)
        # 2026-08-05 is a Wednesday (weekday()==2), 14:xx UTC
        main.collection.insert_many([
            {"timestamp": "2026-08-05T14:10:00Z"},
            {"timestamp": "2026-08-05T14:45:00Z"},
            {"timestamp": "2026-08-05T09:00:00Z"},
            {"timestamp": None},          # ignored, not counted, doesn't crash
            {"timestamp": "not-a-date"},  # ignored, not counted, doesn't crash
        ])

        r = client.get("/api/stats/heatmap")

        assert r.status_code == 200
        data = r.json()["data"]
        assert len(data) == 7 * 24
        by_key = {(d["day"], d["hour"]): d["count"] for d in data}
        assert by_key[(2, 14)] == 2
        assert by_key[(2, 9)] == 1
        assert sum(by_key.values()) == 3


# ---------------------------------------------------------------------------
# /api/sessions/human-likely: heuristic bot-vs-human classification based on
# inter-command timing and a known scripted-bot command-prefix match.
# ---------------------------------------------------------------------------
def _command_docs(session, src_ip, commands, timestamps, country="Vietnam"):
    return [
        {
            "session": session, "src_ip": src_ip, "country": country,
            "event": "cowrie.command.input", "command": cmd, "timestamp": ts,
        }
        for cmd, ts in zip(commands, timestamps)
    ]


class TestHumanLikelySessions:
    def test_hl01_fast_repeated_bot_prefix_is_flagged_as_bot(self, fresh_app):
        client, main, auth = _login(fresh_app)
        main.collection.insert_many(_command_docs(
            "sessA", "203.0.113.7",
            ["sh", "shell", "enable", "system", "ping; sh"],
            ["2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:00.200000Z",
             "2026-01-01T00:00:00.400000Z", "2026-01-01T00:00:00.600000Z",
             "2026-01-01T00:00:00.800000Z"],
        ))

        r = client.get("/api/sessions/human-likely")

        assert r.status_code == 200
        data = r.json()["data"]
        assert len(data) == 1
        assert data[0]["likely_human"] is False
        assert data[0]["command_count"] == 5

    def test_hl02_slow_distinct_commands_are_flagged_as_likely_human(self, fresh_app):
        client, main, auth = _login(fresh_app)
        main.collection.insert_many(_command_docs(
            "sessB", "198.51.100.9",
            ["ls -la", "cat /etc/passwd", "whoami"],
            ["2026-01-01T00:00:00Z", "2026-01-01T00:00:08Z", "2026-01-01T00:00:20Z"],
        ))

        r = client.get("/api/sessions/human-likely")

        data = r.json()["data"]
        assert len(data) == 1
        assert data[0]["likely_human"] is True
        assert data[0]["avg_gap_seconds"] > 3.0

    def test_hl03_sessions_with_fewer_than_2_commands_are_excluded(self, fresh_app):
        client, main, auth = _login(fresh_app)
        main.collection.insert_many(_command_docs(
            "sessC", "203.0.113.7", ["whoami"], ["2026-01-01T00:00:00Z"],
        ))

        r = client.get("/api/sessions/human-likely")

        assert r.json()["data"] == []

    def test_hl04_likely_human_sessions_sort_first(self, fresh_app):
        client, main, auth = _login(fresh_app)
        main.collection.insert_many(_command_docs(
            "bot1", "203.0.113.7",
            ["sh", "shell", "enable", "system", "ping; sh"],
            ["2026-01-01T00:00:00.0Z", "2026-01-01T00:00:00.1Z",
             "2026-01-01T00:00:00.2Z", "2026-01-01T00:00:00.3Z",
             "2026-01-01T00:00:00.4Z"],
        ))
        main.collection.insert_many(_command_docs(
            "human1", "198.51.100.9",
            ["ls", "cat notes.txt"],
            ["2026-01-01T00:00:00Z", "2026-01-01T00:00:10Z"],
        ))

        data = client.get("/api/sessions/human-likely").json()["data"]

        assert data[0]["session"] == "human1"
        assert data[0]["likely_human"] is True


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


ADMIN_ONLY_ENDPOINTS = ["/api/export/csv", "/api/alerts/pending", "/api/auth-log", "/api/auth-log/verify"]
VIEWER_ALLOWED_ENDPOINTS = [
    "/api/stats", "/api/attacks", "/api/top-ips", "/api/top-passwords",
    "/api/top-usernames", "/api/map-data", "/api/stats/hourly",
    "/api/stats/countries", "/api/brute-force", "/api/search?ip=1.2.3.4",
    "/api/sessions/human-likely", "/api/stats/mitre", "/api/stats/heatmap",
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


# ---------------------------------------------------------------------------
# /api/auth-log and /api/auth-log/verify: the hash-chained, tamper-evident
# audit log (see parser/auth.py's log_auth_event/verify_auth_log_integrity).
# ---------------------------------------------------------------------------
class TestAuthLogEndpoints:
    def test_authlog01_list_reflects_login_attempts_newest_first(self, fresh_app):
        client, main, auth = _login(fresh_app)  # 1 successful login already logged
        client.post("/auth/login", json={"username": "admin", "password": "wrong"})

        r = client.get("/api/auth-log")

        assert r.status_code == 200
        data = r.json()["data"]
        assert len(data) == 2
        assert data[0]["success"] is False  # newest (the failed attempt) first
        assert data[1]["success"] is True

    def test_authlog02_list_never_exposes_the_hash_chain_fields(self, fresh_app):
        """entry_hash/prev_hash are internal integrity-check plumbing, not
        something the dashboard needs to render - keep the response
        focused on human-readable fields."""
        client, main, auth = _login(fresh_app)

        r = client.get("/api/auth-log")

        entry = r.json()["data"][0]
        assert "entry_hash" not in entry
        assert "prev_hash" not in entry
        assert "seq" in entry  # still useful for ordering/debugging

    def test_authlog03_verify_reports_ok_on_an_untampered_chain(self, fresh_app):
        client, main, auth = _login(fresh_app)
        client.post("/auth/login", json={"username": "admin", "password": "wrong"})

        r = client.get("/api/auth-log/verify")

        assert r.status_code == 200
        assert r.json() == {"ok": True, "checked": 2, "broken_at_seq": None}

    def test_authlog04_verify_detects_a_tampered_entry(self, fresh_app):
        client, main, auth = _login(fresh_app)
        auth.auth_log_col.update_one({"seq": 0}, {"$set": {"success": False}})

        r = client.get("/api/auth-log/verify")

        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False
        assert body["broken_at_seq"] == 0
