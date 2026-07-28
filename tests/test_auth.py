"""
Layer 4 test plan: Auth / JWT (AU-01 .. AU-30 from the test plan table).

Uses the `fresh_app` fixture (conftest.py): a fresh parser/main.py +
parser/auth.py import pair, mongomock-backed, wrapped in a TestClient.
Same safety guarantee as layers 2/3: never touches the real "honeypot"
MongoDB database, no matter what a test does.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


def _register_user(auth_module, username="admin", password="S3cure!Pass123"):
    auth_module.users_col.insert_one(
        {
            "username": username,
            "password_hash": auth_module.hash_password(password),
            "created_at": auth_module._now(),
        }
    )
    return username, password


# ---------------------------------------------------------------------------
# AU-01, AU-02, AU-03, AU-04
# ---------------------------------------------------------------------------
class TestLogin:
    def test_au01_correct_login_sets_cookies_and_csrf(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)

        r = client.post("/auth/login", json={"username": username, "password": password})

        assert r.status_code == 200
        body = r.json()
        assert body["username"] == username
        assert "csrf_token" in body
        assert client.cookies.get("access_token")
        assert client.cookies.get("refresh_token")
        assert client.cookies.get("csrf_token") == body["csrf_token"]

    def test_au02_wrong_password_generic_error(self, fresh_app):
        client, main, auth = fresh_app
        username, _ = _register_user(auth)

        r = client.post("/auth/login", json={"username": username, "password": "wrong"})

        assert r.status_code == 401
        assert r.json()["detail"] == "Sai thông tin đăng nhập"

    def test_au03_nonexistent_username_same_generic_error(self, fresh_app):
        client, main, auth = fresh_app
        _register_user(auth)  # some user exists, but we try a different one

        r = client.post("/auth/login", json={"username": "ghost", "password": "whatever"})

        assert r.status_code == 401
        assert r.json()["detail"] == "Sai thông tin đăng nhập"

    def test_au04_timing_side_channel_is_not_grossly_different(self, fresh_app):
        """
        Best-effort check, not a hard security gate - real timing side
        channels are sub-millisecond and this sandboxed environment is
        noisy. Asserts the two paths stay within the same order of
        magnitude (ratio < 3x) rather than a tight absolute bound, to
        avoid flaky failures on a loaded machine.
        """
        client, main, auth = fresh_app
        username, _ = _register_user(auth)

        def timed(username_to_try, n=15):
            start = time.perf_counter()
            for _ in range(n):
                client.post("/auth/login", json={"username": username_to_try, "password": "wrong"})
                auth.login_attempts_col.delete_many({})  # isolate timing from AU-10's lockout
            return (time.perf_counter() - start) / n

        existing_user_time = timed(username)
        nonexistent_user_time = timed("definitely-not-a-real-user")

        ratio = max(existing_user_time, nonexistent_user_time) / min(
            existing_user_time, nonexistent_user_time
        )
        assert ratio < 3, (
            f"existing-user path took {existing_user_time * 1000:.2f}ms vs "
            f"nonexistent-user path {nonexistent_user_time * 1000:.2f}ms avg - "
            "gap large enough it might leak whether a username exists"
        )


# ---------------------------------------------------------------------------
# AU-05, AU-06, AU-07, AU-08, AU-09
# ---------------------------------------------------------------------------
class TestInjectionAndMalformedInput:
    def test_au05_nosql_injection_via_username_rejected_by_validation(self, fresh_app):
        client, main, auth = fresh_app
        r = client.post("/auth/login", json={"username": {"$ne": None}, "password": "x"})
        assert r.status_code == 422

    def test_au06_nosql_injection_via_password_rejected_by_validation(self, fresh_app):
        client, main, auth = fresh_app
        r = client.post("/auth/login", json={"username": "admin", "password": {"$regex": ".*"}})
        assert r.status_code == 422

    def test_au07_xss_payload_as_username_is_just_a_failed_login(self, fresh_app):
        """
        The login endpoint has no XSS surface itself (JSON in, JSON out,
        no HTML rendering) - a script-tag username simply fails to
        authenticate. The real XSS risk from attacker-controlled strings
        is in the dashboard's rendering of honeypot data, tested
        separately in the Dashboard layer.
        """
        client, main, auth = fresh_app
        r = client.post(
            "/auth/login",
            json={"username": "<script>alert(1)</script>", "password": "whatever"},
        )
        assert r.status_code == 401
        assert r.json()["detail"] == "Sai thông tin đăng nhập"

    def test_au08_empty_credentials(self, fresh_app):
        client, main, auth = fresh_app
        r = client.post("/auth/login", json={"username": "", "password": ""})
        assert r.status_code == 401

    def test_au09_overlong_password_fails_gracefully_instead_of_crashing(self, fresh_app):
        """
        bcrypt 5.x raises ValueError for passwords over 72 bytes.
        auth.authenticate_user() now checks the length up front and treats
        an over-length password as a normal failed login (same generic
        message, no crash) instead of letting bcrypt's exception escape.
        """
        client, main, auth = fresh_app
        username, _ = _register_user(auth)

        r = client.post(
            "/auth/login", json={"username": username, "password": "a" * 100000}
        )

        assert r.status_code == 401
        assert r.json()["detail"] == "Sai thông tin đăng nhập"

    def test_au09_overlong_password_against_nonexistent_user_also_fails_gracefully(
        self, fresh_app
    ):
        client, main, auth = fresh_app

        r = client.post(
            "/auth/login", json={"username": "ghost", "password": "a" * 100000}
        )

        assert r.status_code == 401
        assert r.json()["detail"] == "Sai thông tin đăng nhập"

    def test_au09_hash_password_rejects_overlong_password_with_clear_error(self, fresh_app):
        """create_admin.py calls hash_password() directly (no HTTP layer,
        no length check upstream) - it must raise a clear, catchable error
        rather than bcrypt's raw ValueError so the CLI can report it
        sensibly, not crash with a stack trace."""
        client, main, auth = fresh_app

        with pytest.raises(ValueError, match="72 bytes"):
            auth.hash_password("a" * 100000)

    def test_au09_verify_password_rejects_overlong_password_without_crashing(self, fresh_app):
        client, main, auth = fresh_app
        _, password = _register_user(auth, username="someone", password="NormalPass1!")
        password_hash = auth.hash_password(password)

        assert auth.verify_password("a" * 100000, password_hash) is False


# ---------------------------------------------------------------------------
# AU-10 .. AU-14: brute-force lockout
# ---------------------------------------------------------------------------
class TestBruteForceLockout:
    def test_au10_locks_out_after_five_failed_attempts(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)

        for _ in range(5):
            r = client.post("/auth/login", json={"username": username, "password": "wrong"})
            assert r.status_code == 401

        r = client.post("/auth/login", json={"username": username, "password": password})

        assert r.status_code == 429
        assert "Quá nhiều lần đăng nhập sai" in r.json()["detail"]

    def test_au11_lockout_is_stored_in_mongo_not_in_process_memory(self, fresh_app):
        """
        Proves lockout state lives in a Mongo collection (login_attempts),
        not a Python-process-local variable. Since Mongo is external to
        the API process, this structurally means a real API restart does
        not clear an active lockout - nothing resets this collection on
        startup.
        """
        client, main, auth = fresh_app
        username, _ = _register_user(auth)

        for _ in range(5):
            client.post("/auth/login", json={"username": username, "password": "wrong"})

        doc = auth.login_attempts_col.find_one({"key": f"testclient|{username.lower()}"})
        assert doc is not None
        assert doc["locked_until"] is not None

    def test_au12_bypassed_by_switching_source_ip(self, fresh_app):
        """
        The rate-limit key is (ip, username) - tested directly at the
        function level since this TestClient/Starlette version has no way
        to fake request.client.host per-request. This is a documented,
        deliberate trade-off (see README): it stops a single-IP attacker
        but not a botnet trying the same username from many IPs.
        """
        client, main, auth = fresh_app
        username, _ = _register_user(auth)

        for _ in range(5):
            auth.record_failed_attempt("10.0.0.1", username)
        with pytest.raises(HTTPException) as exc_info:
            auth.check_rate_limit("10.0.0.1", username)
        assert exc_info.value.status_code == 429

        auth.check_rate_limit("10.0.0.2", username)  # different IP -> must not raise

    def test_au13_not_bypassed_by_switching_user_agent(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)

        for _ in range(5):
            client.post(
                "/auth/login",
                json={"username": username, "password": "wrong"},
                headers={"User-Agent": "Mozilla/5.0 attacker-bot-v1"},
            )

        r = client.post(
            "/auth/login",
            json={"username": username, "password": password},
            headers={"User-Agent": "curl/8.0 totally-different-agent"},
        )

        assert r.status_code == 429

    def test_au14_successful_login_resets_lockout_counter(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)

        for _ in range(3):  # under the 5-attempt threshold
            client.post("/auth/login", json={"username": username, "password": "wrong"})

        r = client.post("/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200

        doc = auth.login_attempts_col.find_one({"key": f"testclient|{username.lower()}"})
        assert doc is None


# ---------------------------------------------------------------------------
# AU-15 .. AU-19: token validation, expiry, tampering, alg confusion
# ---------------------------------------------------------------------------
class TestTokenValidation:
    def test_au15_no_token_at_all(self, fresh_app):
        client, main, auth = fresh_app
        r = client.get("/api/stats")
        assert r.status_code == 401

    def test_au16_expired_token_is_rejected(self, fresh_app):
        client, main, auth = fresh_app
        expired_payload = {
            "sub": "admin",
            "type": "access",
            "jti": "x",
            "iat": datetime.utcnow() - timedelta(hours=2),
            "exp": datetime.utcnow() - timedelta(hours=1),
        }
        expired_token = jwt.encode(expired_payload, auth.SECRET_KEY, algorithm=auth.ALGORITHM)
        client.cookies.set("access_token", expired_token)

        r = client.get("/api/stats")

        assert r.status_code == 401

    def test_au17_tampered_token_is_rejected(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        client.post("/auth/login", json={"username": username, "password": password})
        token = client.cookies.get("access_token")

        # Flip the FIRST character of the signature segment, not the last:
        # the last base64url character of a JWT signature can encode
        # padding-only bits, so flipping it has a small chance of decoding
        # to the same underlying byte value (a no-op "tamper"). The first
        # character always encodes fully significant bits.
        header, payload, signature = token.split(".")
        tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        tampered = f"{header}.{payload}.{tampered_signature}"
        client.cookies.set("access_token", tampered)

        r = client.get("/api/stats")

        assert r.status_code == 401

    def test_au18_alg_none_token_is_rejected(self, fresh_app):
        """
        Classic JWT vulnerability: an attacker crafts an unsigned token
        with `"alg": "none"`, hoping a lenient verifier accepts it without
        checking any signature. auth.decode_token() pins
        `algorithms=[ALGORITHM]` (HS256 only) on jwt.decode(), so PyJWT
        itself refuses to even consider a none-alg token.
        """
        client, main, auth = fresh_app
        none_alg_token = jwt.encode(
            {"sub": "admin", "type": "access", "exp": datetime.utcnow() + timedelta(hours=1)},
            key="",
            algorithm="none",
        )
        client.cookies.set("access_token", none_alg_token)

        r = client.get("/api/stats")

        assert r.status_code == 401

    def test_au19_wrong_secret_rejected_alg_confusion_not_applicable(self, fresh_app):
        """
        HS256/RS256 "key confusion" requires the verifier to also accept
        RS256 with some asymmetric public key an attacker could re-sign
        with as an HMAC secret. This app only ever uses one symmetric
        HS256 secret - there is no public key anywhere to repurpose, so
        the classic confusion attack has no foothold here. This just
        confirms a token signed with an arbitrary wrong secret is
        rejected.
        """
        client, main, auth = fresh_app
        wrong_secret_token = jwt.encode(
            {"sub": "admin", "type": "access", "exp": datetime.utcnow() + timedelta(hours=1)},
            key="some-other-guessed-secret",
            algorithm="HS256",
        )
        client.cookies.set("access_token", wrong_secret_token)

        r = client.get("/api/stats")

        assert r.status_code == 401


# ---------------------------------------------------------------------------
# AU-20 .. AU-24: refresh/logout token lifecycle
# ---------------------------------------------------------------------------
class TestRefreshAndLogout:
    def test_au20_refresh_token_rejected_as_access_token(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        client.post("/auth/login", json={"username": username, "password": password})
        refresh_token = client.cookies.get("refresh_token")

        client.cookies.set("access_token", refresh_token)
        r = client.get("/api/stats")

        assert r.status_code == 401

    def test_au21_refresh_issues_new_tokens_and_rotates_old_one(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        login = client.post("/auth/login", json={"username": username, "password": password})
        csrf = login.json()["csrf_token"]
        old_refresh = client.cookies.get("refresh_token")

        r = client.post("/auth/refresh", headers={"X-CSRF-Token": csrf})

        assert r.status_code == 200
        assert client.cookies.get("refresh_token") != old_refresh

    def test_au22_rotated_refresh_token_cannot_be_reused(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        login = client.post("/auth/login", json={"username": username, "password": password})
        csrf = login.json()["csrf_token"]
        old_refresh = client.cookies.get("refresh_token")

        client.post("/auth/refresh", headers={"X-CSRF-Token": csrf})  # rotates it

        client.cookies.set("refresh_token", old_refresh)
        r = client.post("/auth/refresh", headers={"X-CSRF-Token": csrf})

        assert r.status_code == 401

    def test_au23_access_token_still_valid_after_logout_until_natural_expiry(self, fresh_app):
        """
        Documented, deliberate trade-off (see README): access tokens are
        stateless (no DB lookup on every request), so there is no
        blacklist for them. Logout only revokes the refresh token - a
        retained access token keeps working until it naturally expires
        (ACCESS_TOKEN_EXPIRE_MINUTES = 90 minutes).
        """
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        login = client.post("/auth/login", json={"username": username, "password": password})
        csrf = login.json()["csrf_token"]
        access_token_before_logout = client.cookies.get("access_token")

        client.post("/auth/logout", headers={"X-CSRF-Token": csrf})

        client.cookies.set("access_token", access_token_before_logout)
        r = client.get("/api/stats")

        assert r.status_code == 200

    def test_au24_refresh_token_revoked_immediately_on_logout(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        login = client.post("/auth/login", json={"username": username, "password": password})
        csrf = login.json()["csrf_token"]
        refresh_token_before_logout = client.cookies.get("refresh_token")

        client.post("/auth/logout", headers={"X-CSRF-Token": csrf})
        # logout deletes the csrf_token cookie along with the JWT cookies -
        # restore it so this specifically isolates "was the refresh token
        # revoked?" from the separate CSRF check (already covered by AU-25/26).
        client.cookies.set("refresh_token", refresh_token_before_logout)
        client.cookies.set("csrf_token", csrf)
        r = client.post("/auth/refresh", headers={"X-CSRF-Token": csrf})

        assert r.status_code == 401


# ---------------------------------------------------------------------------
# AU-25, AU-26: CSRF (double-submit cookie)
# ---------------------------------------------------------------------------
class TestCSRF:
    def test_au25_logout_without_csrf_header_is_rejected(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        client.post("/auth/login", json={"username": username, "password": password})

        r = client.post("/auth/logout")

        assert r.status_code == 403

    def test_au26_csrf_header_not_matching_cookie_is_rejected(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)
        client.post("/auth/login", json={"username": username, "password": password})

        r = client.post("/auth/logout", headers={"X-CSRF-Token": "totally-wrong-value"})

        assert r.status_code == 403


# ---------------------------------------------------------------------------
# AU-27: authorization model (no RBAC/IDOR to test - documented gap)
# ---------------------------------------------------------------------------
class TestAuthorizationModel:
    def test_au27_no_rbac_any_two_accounts_see_identical_data(self, fresh_app):
        """
        DOCUMENTED GAP: there is no role/ownership field anywhere in the
        `users` collection and no per-user filtering on any /api/* route -
        a deliberate single-tenant admin design, not a bug. This means
        classic IDOR testing ("does account B see account A's private
        record?") doesn't apply: there is no such thing as "account A's
        record" here. Confirming that explicitly rather than silently
        skipping the case.
        """
        client, main, auth = fresh_app
        auth.users_col.insert_one(
            {"username": "admin1", "password_hash": auth.hash_password("Pass123!aa"), "created_at": auth._now()}
        )
        auth.users_col.insert_one(
            {"username": "admin2", "password_hash": auth.hash_password("Pass456!bb"), "created_at": auth._now()}
        )
        main.collection.insert_one({"src_ip": "203.0.113.7", "event": "cowrie.login.failed"})

        client_1 = client
        client_2 = TestClient(main.app)

        client_1.post("/auth/login", json={"username": "admin1", "password": "Pass123!aa"})
        client_2.post("/auth/login", json={"username": "admin2", "password": "Pass456!bb"})

        data_1 = client_1.get("/api/stats").json()
        data_2 = client_2.get("/api/stats").json()

        assert data_1 == data_2  # both accounts see the exact same (only) tenant's data


# ---------------------------------------------------------------------------
# AU-28, AU-29: login attempts are logged
# ---------------------------------------------------------------------------
class TestAuthLogging:
    def test_au28_failed_login_is_logged(self, fresh_app):
        client, main, auth = fresh_app
        username, _ = _register_user(auth)

        client.post(
            "/auth/login",
            json={"username": username, "password": "wrong"},
            headers={"User-Agent": "test-agent"},
        )

        doc = auth.auth_log_col.find_one({"username": username, "success": False})
        assert doc is not None
        assert doc["ip"] == "testclient"
        assert doc["user_agent"] == "test-agent"
        assert "timestamp" in doc

    def test_au29_successful_login_is_logged(self, fresh_app):
        client, main, auth = fresh_app
        username, password = _register_user(auth)

        client.post("/auth/login", json={"username": username, "password": password})

        doc = auth.auth_log_col.find_one({"username": username, "success": True})
        assert doc is not None


# ---------------------------------------------------------------------------
# AU-30: CORS
# ---------------------------------------------------------------------------
class TestCORS:
    def test_au30_cors_allows_configured_dashboard_origin(self, fresh_app):
        client, main, auth = fresh_app
        r = client.options(
            "/auth/login",
            headers={"Origin": "http://localhost:8080", "Access-Control-Request-Method": "POST"},
        )
        assert r.headers.get("access-control-allow-origin") == "http://localhost:8080"

    def test_au30_cors_rejects_unlisted_origin(self, fresh_app):
        client, main, auth = fresh_app
        r = client.options(
            "/auth/login",
            headers={"Origin": "http://evil.com", "Access-Control-Request-Method": "POST"},
        )
        assert r.status_code == 400
        assert "access-control-allow-origin" not in r.headers
