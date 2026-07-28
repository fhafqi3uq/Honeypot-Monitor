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
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
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
    def test_db05_xss_payload_in_username_executes_in_browser(self, page, live_stack_clean):
        """
        THE most important finding in this whole test plan: app.js's
        updateTable() (and attacks.html's equivalent) inserts a.username /
        a.password / a.command straight into innerHTML via a template
        string, with no escaping. An attacker who gets the honeypot to
        record a username/password/command containing a script tag gets
        that script executed in the logged-in admin's browser the next
        time they open the dashboard - and since the csrf_token cookie is
        deliberately NOT httpOnly (the double-submit CSRF design requires
        JS to read it), injected script can read it and forge a valid
        CSRF-protected request as the admin, e.g. to /auth/logout or any
        future mutating endpoint.
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

        try:
            page.wait_for_function("window.__xss_fired === true", timeout=5000)
        except PlaywrightTimeoutError:
            pytest.fail(
                "XSS payload in username did NOT execute - if the dashboard now "
                "escapes attacker-controlled fields, update/remove this test "
                "(that would mean this known vulnerability has been fixed)."
            )


# ---------------------------------------------------------------------------
# DB-06: session expiring mid-use
# ---------------------------------------------------------------------------
class TestSessionExpiry:
    def test_db06_invalidated_session_shows_silent_empty_data_not_a_redirect(
        self, page, live_stack_clean
    ):
        """
        Documents a known gap: the dashboard only checks the session once,
        at page load (requireAuth()). If the session becomes invalid while
        the page is already open, clicking "Làm mới" silently shows empty/
        zeroed data (data.js's fetch helpers catch errors and return
        defaults) instead of detecting the 401 and redirecting to login.
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
        page.wait_for_timeout(1000)

        # fetch() doesn't reject on an HTTP 401 - fetchStats() happily
        # parses the {"detail": "..."} error body as if it were the real
        # stats object, so stat-total ends up blank/garbled rather than
        # showing an error or the correct "1". The exact garbled value
        # isn't the point - what matters is it's silently WRONG, and nothing
        # tells the admin their session died mid-use.
        expect(page.locator("#stat-total")).not_to_have_text("1")
        assert "login.html" not in page.url, (
            "the dashboard redirected to login on an invalidated session mid-use - "
            "if this is now handled, update/remove this test and its docstring"
        )


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
# DB-08: map.html is missing the "Tìm kiếm IP" nav link (pre-existing bug)
# ---------------------------------------------------------------------------
class TestKnownNavBug:
    def test_db08_map_page_nav_is_missing_search_link(self, page, live_stack_clean):
        """
        Pre-existing, non-security bug: every other page's sidebar has 5
        nav links (Dashboard/Tấn công/Thống kê/Bản đồ/Tìm kiếm IP), but
        map.html only has 4 - it's missing "Tìm kiếm IP". Documented here
        so this doesn't get silently "fixed" without anyone noticing the
        inconsistency was real, and so a real fix updates this test.
        """
        _, dashboard_url, test_db = live_stack_clean
        username, password = _seed_user(test_db)
        _login_via_ui(page, dashboard_url, username, password)

        page.goto(f"{dashboard_url}/map.html")
        nav_links = page.locator(".sidebar nav a").all_text_contents()

        assert not any("Tìm kiếm" in text for text in nav_links), (
            "map.html now has the 'Tìm kiếm IP' link - if this bug was fixed, "
            "update/remove this test."
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
