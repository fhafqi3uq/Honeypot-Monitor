"""
Layer 6 test plan: Dashboard (DB-01 .. DB-09 from the test plan table).

Uses the `live_stack`/`live_stack_clean` fixtures (conftest.py): a REAL
uvicorn (parser/main.py) and a REAL live-server (dashboard/) launched as
subprocesses, pointed at an isolated "honeypot_test" MongoDB database
(never "honeypot", the production database) via MONGO_URL/DB_NAME env
vars. Driven with a real headless Chromium browser via pytest-playwright's
`page` fixture, since this layer specifically needs real HTTP/cookie/CORS/
JS behaviour that TestClient can't replicate.
"""

from __future__ import annotations

from datetime import datetime

import bcrypt
import pytest
from playwright.sync_api import expect

PAGES = ["index.html", "attacks.html", "stats.html", "map.html", "search.html"]


@pytest.fixture
def page(page, live_stack_clean):
    """
    Overrides pytest-playwright's `page` fixture: dashboard/js/data.js
    (and map.html/search.html, which inline their own copy) hardcode
    `API_URL = "http://localhost:8000"` - not configurable via env. Rather
    than either running the test API on port 8000 (risking a collision
    with a real start.sh-launched production stack) or editing the real
    frontend source, transparently redirect any request the browser makes
    to localhost:8000 over to this session's actual isolated test port.
    The real, unmodified dashboard/API code is still what's under test.
    """
    api_url, _, _ = live_stack_clean

    def _redirect_to_test_api(route):
        route.continue_(url=route.request.url.replace("http://localhost:8000", api_url))

    page.route("http://localhost:8000/**", _redirect_to_test_api)
    yield page


def _seed_user(test_db, username="admin", password="Pass123!Aa"):
    test_db.users.insert_one(
        {
            "username": username,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "created_at": datetime.utcnow(),
        }
    )
    return username, password


def _login_via_ui(page, dashboard_url, username, password):
    page.goto(f"{dashboard_url}/login.html")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#btn-login")
    page.wait_for_url(f"{dashboard_url}/index.html", timeout=5000)


# ---------------------------------------------------------------------------
# DB-01: dashboard data matches the database
# ---------------------------------------------------------------------------
class TestDataAccuracy:
    def test_db01_dashboard_shows_correct_counts_from_db(self, page, live_stack_clean):
        api_url, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        test_db.attacks.insert_many(
            [
                {"event": "cowrie.login.failed", "src_ip": "1.2.3.4", "timestamp": "2026-01-01T00:00:00"},
                {"event": "cowrie.login.failed", "src_ip": "1.2.3.5", "timestamp": "2026-01-01T00:00:01"},
                {"event": "cowrie.login.success", "src_ip": "1.2.3.6", "timestamp": "2026-01-01T00:00:02"},
            ]
        )

        _login_via_ui(page, dashboard_url, username, password)

        expect(page.locator("#stat-total")).to_have_text("3")
        expect(page.locator("#stat-failed")).to_have_text("2")
        expect(page.locator("#stat-success")).to_have_text("1")


# ---------------------------------------------------------------------------
# DB-02: every protected page redirects to login.html when not authenticated
# ---------------------------------------------------------------------------
class TestRouteProtection:
    @pytest.mark.parametrize("path", PAGES)
    def test_db02_unauthenticated_page_redirects_to_login(self, page, live_stack_clean, path):
        _, dashboard_url, _ = live_stack_clean
        page.goto(f"{dashboard_url}/{path}")
        page.wait_for_url(f"{dashboard_url}/login.html", timeout=5000)
        assert "login.html" in page.url


# ---------------------------------------------------------------------------
# DB-03: empty database
# ---------------------------------------------------------------------------
class TestEmptyDatabase:
    def test_db03_empty_database_shows_zeros_not_errors(self, page, live_stack_clean):
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)

        _login_via_ui(page, dashboard_url, username, password)

        expect(page.locator("#stat-total")).to_have_text("0")
        expect(page.locator("#stat-failed")).to_have_text("0")
        expect(page.locator("#stat-success")).to_have_text("0")


# ---------------------------------------------------------------------------
# DB-04: large dataset
# ---------------------------------------------------------------------------
class TestLargeDataset:
    def test_db04_large_dataset_loads_and_paginates(self, page, live_stack_clean):
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        test_db.attacks.insert_many(
            [
                {
                    "event": "cowrie.login.failed",
                    "src_ip": f"10.0.{i // 256}.{i % 256}",
                    "timestamp": f"2026-01-01T00:{i % 60:02d}:00",
                }
                for i in range(500)
            ]
        )

        _login_via_ui(page, dashboard_url, username, password)
        expect(page.locator("#stat-total")).to_have_text("500")

        page.goto(f"{dashboard_url}/attacks.html")
        expect(page.locator("#attack-tbody tr").first).to_be_visible()
        # PAGE_SIZE=20 in attacks.html - 500 rows means multiple page-number
        # buttons must appear, not just a single unpaginated dump of 500 rows.
        page_button_count = page.locator(".page-btn").count()
        assert page_button_count > 1, f"expected pagination controls, found {page_button_count} .page-btn elements"


# ---------------------------------------------------------------------------
# DB-05: stored XSS via honeypot-controlled fields (username/password/command)
# ---------------------------------------------------------------------------
class TestStoredXSS:
    def test_db05_xss_payload_in_username_does_not_execute(self, page, live_stack_clean):
        """
        Regression test for a real vulnerability found and fixed in this
        project: app.js's updateTable() (and the equivalent render
        functions in attacks.html/search.html/stats.html/map.html) used to
        insert a.username/a.password/a.command/etc. straight into
        innerHTML via a template string, with no escaping. An attacker who
        got the honeypot to record a username/password/command containing
        a script tag got that script executed in the logged-in admin's
        browser the next time the dashboard rendered it - and since the
        csrf_token cookie is deliberately not httpOnly (the double-submit
        CSRF design needs JS to read it), injected script could forge a
        valid CSRF-protected request as the admin too.

        Fixed via a shared `escapeHtml()` helper (dashboard/js/escape.js)
        applied to every attacker-controlled field before it's
        interpolated into an HTML template. This test proves the payload
        no longer executes AND that it's still shown to the admin as
        inert, escaped text (not silently dropped).
        """
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        xss_payload = '<img src=x onerror="window.__xss_fired=true">'
        test_db.attacks.insert_one(
            {
                "event": "cowrie.login.failed",
                "src_ip": "203.0.113.7",
                "username": xss_payload,
                "password": "whatever",
                "timestamp": "2026-01-01T00:00:00",
            }
        )

        _login_via_ui(page, dashboard_url, username, password)
        expect(page.locator("#attack-tbody tr").first).to_be_visible()

        fired = page.evaluate("window.__xss_fired === true")
        assert not fired, "XSS payload in username executed - escaping regressed"

        # The payload must still be visible to the admin, just as literal
        # (escaped) text, not silently stripped/hidden.
        row_text = page.locator("#attack-tbody tr").first.inner_text()
        assert "img src=x" in row_text

    def test_db05_xss_payload_does_not_execute_on_attacks_page(self, page, live_stack_clean):
        """Same escaping fix, checked on attacks.html's own (separate)
        render function - a different file than index.html/app.js, so a
        typo fixing one wouldn't be caught by the other's test."""
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        xss_payload = '<img src=x onerror="window.__xss_fired=true">'
        test_db.attacks.insert_one(
            {
                "event": "cowrie.login.failed",
                "src_ip": "203.0.113.7",
                "username": xss_payload,
                "password": "whatever",
                "timestamp": "2026-01-01T00:00:00",
            }
        )

        _login_via_ui(page, dashboard_url, username, password)
        page.goto(f"{dashboard_url}/attacks.html")
        expect(page.locator("#attack-tbody tr").first).to_be_visible()

        assert page.evaluate("window.__xss_fired === true") is not True

    def test_db05_xss_payload_does_not_execute_on_stats_page(self, page, live_stack_clean):
        """Same fix, checked on stats.html's top-passwords list - password
        is directly attacker-typed input, and this is a third, separately
        maintained render function."""
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        xss_payload = '<img src=x onerror="window.__xss_fired=true">'
        test_db.attacks.insert_one(
            {
                "event": "cowrie.login.failed",
                "src_ip": "203.0.113.7",
                "username": "root",
                "password": xss_payload,
                "timestamp": "2026-01-01T00:00:00",
            }
        )

        _login_via_ui(page, dashboard_url, username, password)
        page.goto(f"{dashboard_url}/stats.html")
        expect(page.locator("#top-passwords tr").first).to_be_visible()

        assert page.evaluate("window.__xss_fired === true") is not True


# ---------------------------------------------------------------------------
# DB-06: session expiring mid-use
# ---------------------------------------------------------------------------
class TestSessionExpiry:
    def test_db06_invalidated_session_redirects_to_login(
        self, page, live_stack_clean
    ):
        """
        Regression test for a fixed gap: the dashboard used to only check
        the session once, at page load (requireAuth()). If the session
        became invalid while the page was already open, clicking "Làm mới"
        would silently show empty/zeroed data (fetch() does not reject on
        an HTTP 401) instead of detecting it and redirecting to login.
        authFetch() (js/auth.js) now checks every response's status and
        redirects to login.html on a 401.
        """
        api_url, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        test_db.attacks.insert_one(
            {"event": "cowrie.login.failed", "src_ip": "1.2.3.4", "timestamp": "2026-01-01T00:00:00"}
        )

        _login_via_ui(page, dashboard_url, username, password)
        expect(page.locator("#stat-total")).to_have_text("1")

        page.context.add_cookies(
            [
                {
                    "name": "access_token",
                    "value": "this-is-not-a-valid-jwt",
                    "domain": "localhost",
                    "path": "/",
                }
            ]
        )

        page.click(".btn-refresh")
        page.wait_for_url(f"{dashboard_url}/login.html", timeout=5000)


# ---------------------------------------------------------------------------
# DB-07: logout button
# ---------------------------------------------------------------------------
class TestLogout:
    def test_db07_logout_button_clears_session(self, page, live_stack_clean):
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        _login_via_ui(page, dashboard_url, username, password)

        page.click(".btn-logout")
        page.wait_for_url(f"{dashboard_url}/login.html", timeout=5000)

        # Session is gone - going back to a protected page bounces to login again.
        page.goto(f"{dashboard_url}/index.html")
        page.wait_for_url(f"{dashboard_url}/login.html", timeout=5000)


# ---------------------------------------------------------------------------
# DB-08: map.html nav now matches the other 4 dashboard pages
# ---------------------------------------------------------------------------
class TestKnownNavBug:
    def test_db08_map_page_nav_has_search_link(self, page, live_stack_clean):
        """
        Every dashboard page's sidebar should have the same 5 nav links
        (Dashboard/Tấn công/Thống kê/Bản đồ/Tìm kiếm IP). map.html used to
        be missing "Tìm kiếm IP" - now fixed, so it should match.
        """
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        _login_via_ui(page, dashboard_url, username, password)

        page.goto(f"{dashboard_url}/map.html")
        nav_links = page.locator(".sidebar nav a").all_text_contents()

        assert any("Tìm kiếm" in text for text in nav_links), (
            "map.html is missing the 'Tìm kiếm IP' nav link again"
        )


# ---------------------------------------------------------------------------
# DB-09: responsive/mobile layout
# ---------------------------------------------------------------------------
class TestResponsive:
    def test_db09_mobile_viewport_shows_menu_toggle_and_sidebar_opens(self, page, live_stack_clean):
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        _login_via_ui(page, dashboard_url, username, password)

        page.set_viewport_size({"width": 375, "height": 667})

        expect(page.locator(".menu-toggle")).to_be_visible()
        assert "open" not in (page.locator("#sidebar").get_attribute("class") or "")

        page.click(".menu-toggle")

        assert "open" in (page.locator("#sidebar").get_attribute("class") or "")
