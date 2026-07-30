"""
Layer 7 test plan: End-to-end integration (E2E-01 .. E2E-05 from the test
plan table).

Real Cowrie honeypot (`cowrie_process`) + the real notifier/realtime_alert.py
watcher running in-process (`e2e_watcher` - Telegram mocked, per the user's
explicit choice not to send real Telegram messages from an automated test)
+ the real API/dashboard (`e2e_dashboard_stack`), all pointed at the
isolated "honeypot_e2e_test" database - never "honeypot", the production
database.

Per the user's decision: real Telegram latency is NOT measured here (that
needs a real bot/chat and would spam it on every run) - E2E-02 measures
attack -> alert-function-called and attack -> MongoDB-visible latency
instead, which is the shared bottleneck Telegram send time sits behind
anyway.
"""

from __future__ import annotations

import time
from datetime import datetime

import bcrypt
import paramiko
import pytest
from playwright.sync_api import expect

from conftest import E2E_DB_NAME, _REAL_MONGO_CLIENT


def _read_until_idle(channel, idle_timeout=1.5, max_wait=10):
    channel.settimeout(0.3)
    buf = b""
    start = time.time()
    last_data = time.time()
    while time.time() - start < max_wait:
        try:
            chunk = channel.recv(4096)
            if chunk:
                buf += chunk
                last_data = time.time()
        except Exception:
            pass
        if time.time() - last_data > idle_timeout:
            break
    return buf.decode(errors="replace")


def _attack(username="root", commands=("whoami", "uname -a", "cat /etc/passwd"), max_login_attempts=6):
    """Plays the attacker against the real Cowrie instance: brute-forces
    through AuthRandom's random 1-3 attempt threshold, then runs a few
    recon commands once in. Caller must client.close()."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connected = False
    for attempt in range(max_login_attempts):
        try:
            client.connect(
                "127.0.0.1", port=2222, username=username, password=f"wrongpass{attempt}",
                timeout=10, allow_agent=False, look_for_keys=False,
            )
            connected = True
            break
        except paramiko.AuthenticationException:
            # AuthRandom's per-source-IP attempt counter is a JSON file
            # read-modified-written on disk with no locking - concurrent
            # attackers from the same IP (127.0.0.1 here) can race on it.
            # A little jitter spreads out retries and makes that race far
            # less likely to matter for what this test actually checks
            # (data isolation once logged in, not Cowrie's own auth-state
            # file concurrency).
            time.sleep(0.2 + 0.3 * (hash((username, attempt)) % 10) / 10)
            continue
    assert connected, "attacker never got past Cowrie's AuthRandom in time"

    chan = client.invoke_shell()
    _read_until_idle(chan)
    outputs = {}
    for cmd in commands:
        chan.send(f"{cmd}\n")
        outputs[cmd] = _read_until_idle(chan)
    return client, outputs


def _seed_dashboard_user(username="admin", password="Pass123!Aa"):
    real_client = _REAL_MONGO_CLIENT("mongodb://localhost:27017")
    db = real_client[E2E_DB_NAME]
    db.users.delete_many({"username": username})
    db.users.insert_one(
        {
            "username": username,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "created_at": datetime.utcnow(),
        }
    )
    real_client.close()
    return username, password


@pytest.fixture
def page(page, e2e_dashboard_stack):
    """Same localhost:8000 -> real test port redirect as the Dashboard
    layer needs (dashboard/js/data.js hardcodes API_URL)."""
    api_url, _ = e2e_dashboard_stack

    def _redirect(route):
        route.continue_(url=route.request.url.replace("http://localhost:8000", api_url))

    page.route("http://localhost:8000/**", _redirect)
    yield page


# ---------------------------------------------------------------------------
# E2E-01: full kill chain, including the human/admin side (dashboard)
# ---------------------------------------------------------------------------
class TestFullKillChain:
    def test_e2e01_attack_reaches_mongo_alerts_and_dashboard(
        self, page, e2e_watcher, e2e_dashboard_stack
    ):
        realtime_alert, mock_send_message, collection = e2e_watcher
        _, dashboard_url = e2e_dashboard_stack
        username, password = _seed_dashboard_user()

        client, outputs = _attack()
        client.close()

        assert "root" in outputs["whoami"]
        assert "Debian" in outputs["uname -a"]

        deadline = time.time() + 10
        while time.time() < deadline:
            if collection.count_documents({"event": "cowrie.login.success"}) > 0:
                break
            time.sleep(0.3)

        # NOT asserting login.failed >= 1 here: honeypot/cowrie-src/etc/
        # cowrie.cfg sets auth_class_parameters = 1,2,3 (mintry=1), so
        # roughly half the time AuthRandom's randomly-chosen threshold is
        # exactly 1 and _attack()'s very first guess succeeds immediately,
        # legitimately producing zero failed attempts first - asserting
        # >= 1 here made this test genuinely flaky (~50%), not a real bug.
        assert collection.count_documents({"event": "cowrie.login.success"}) == 1
        assert collection.count_documents({"event": "cowrie.command.input"}) == len(
            ["whoami", "uname -a", "cat /etc/passwd"]
        )
        assert mock_send_message.call_count >= 1  # alert pipeline actually fired

        # human side: admin logs into the real dashboard and sees the attack
        page.goto(f"{dashboard_url}/login.html")
        page.fill("#username", username)
        page.fill("#password", password)
        page.click("#btn-login")
        page.wait_for_url(f"{dashboard_url}/index.html", timeout=5000)

        expect(page.locator("#stat-success")).to_have_text("1")
        expect(page.locator("#attack-tbody tr").first).to_be_visible()


# ---------------------------------------------------------------------------
# E2E-02: latency from attack to alert pipeline / MongoDB visibility
# ---------------------------------------------------------------------------
class TestLatency:
    def test_e2e02_attack_to_mongo_and_alert_latency(self, e2e_watcher):
        """
        Real Telegram latency isn't measured here (would need a real bot/
        chat and spam it every run - see module docstring). This measures
        the shared bottleneck instead: how long from the attacker's
        successful login until (a) the document is queryable in MongoDB
        and (b) the (mocked) alert function has actually been called -
        both are real numbers usable in a report/CV, just not the final
        "message arrived in Telegram" hop specifically.
        """
        realtime_alert, mock_send_message, collection = e2e_watcher

        t_attack_start = time.time()
        client, _ = _attack(commands=())
        client.close()

        deadline = time.time() + 10
        t_mongo_visible = None
        while time.time() < deadline:
            if collection.count_documents({"event": "cowrie.login.success"}) > 0:
                t_mongo_visible = time.time()
                break
            time.sleep(0.05)

        assert t_mongo_visible is not None, "login.success never appeared in Mongo"
        mongo_latency = t_mongo_visible - t_attack_start
        print(f"\nattack -> MongoDB-visible latency: {mongo_latency:.2f}s")

        deadline = time.time() + 10
        t_alert_called = None
        while time.time() < deadline:
            if mock_send_message.call_count > 0:
                t_alert_called = time.time()
                break
            time.sleep(0.05)

        assert t_alert_called is not None, "alert function was never called"
        alert_latency = t_alert_called - t_attack_start
        print(f"attack -> alert-function-called latency: {alert_latency:.2f}s")

        # Generous bound - this is a demo/report number, not a strict SLA;
        # the point is proving it's seconds, not minutes.
        assert mongo_latency < 10
        assert alert_latency < 10


# ---------------------------------------------------------------------------
# E2E-04: alerting works independent of whether anyone is logged into the
# dashboard; the dashboard itself still gates on login regardless
# ---------------------------------------------------------------------------
class TestAlertingIndependentOfDashboardLogin:
    def test_e2e04_alert_fires_without_any_dashboard_session(self, e2e_watcher):
        realtime_alert, mock_send_message, collection = e2e_watcher

        client, _ = _attack(commands=())
        client.close()

        deadline = time.time() + 10
        while time.time() < deadline:
            if mock_send_message.call_count > 0:
                break
            time.sleep(0.2)

        assert mock_send_message.call_count > 0

    def test_e2e04_dashboard_still_requires_login_regardless(self, page, e2e_dashboard_stack):
        _, dashboard_url = e2e_dashboard_stack
        page.goto(f"{dashboard_url}/index.html")
        page.wait_for_url(f"{dashboard_url}/login.html", timeout=5000)


def _connect_attacker(username, max_login_attempts=10):
    """Just the login phase (retrying through AuthRandom), no commands
    yet - kept separate from running commands so two attackers' *command*
    activity can be run truly concurrently without also racing on
    Cowrie's shared per-source-IP AuthRandom counter (see E2E-05's
    docstring for why that race matters)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connected = False
    for attempt in range(max_login_attempts):
        try:
            client.connect(
                "127.0.0.1", port=2222, username=username, password=f"wrongpass{attempt}",
                timeout=10, allow_agent=False, look_for_keys=False,
            )
            connected = True
            break
        except paramiko.AuthenticationException:
            continue
    assert connected, f"{username} never got past Cowrie's AuthRandom in time"
    chan = client.invoke_shell()
    _read_until_idle(chan)
    return client, chan


# ---------------------------------------------------------------------------
# E2E-05: two concurrent attacker sessions don't bleed into each other
# ---------------------------------------------------------------------------
class TestConcurrentAttackers:
    def test_e2e05_two_simultaneous_sessions_stay_isolated(self, e2e_watcher):
        """
        Cowrie's AuthRandom tracks login attempts per SOURCE IP (not per
        username) in a JSON file: once a specific username:password combo
        has ever succeeded from an IP, EVERY later connection from that
        same IP can only get in again by resending that exact same combo
        (or a combo already in the small global success cache) - a
        different username (e.g. "alice" after "root" already succeeded)
        can no longer succeed via the normal random-threshold path at all.
        Reproduced concretely while writing this test. Real botnets
        commonly reuse the same handful of default credentials anyway, so
        this uses the SAME username for both simulated attackers (as real
        scanners often do) and relies on Cowrie's own session id - not
        username - to prove the two connections' data doesn't bleed
        together, which is the actual point of this test.

        The login phase itself is sequential (see `_connect_attacker`'s
        docstring for the separate, also-real race on that same JSON file
        under true login concurrency); what runs truly concurrently here
        is each attacker's own command activity once both are already
        logged in - the realistic "2 attackers active at once" scenario.
        """
        realtime_alert, mock_send_message, collection = e2e_watcher

        import threading

        client_a, chan_a = _connect_attacker("root")
        client_b, chan_b = _connect_attacker("root")

        outputs = {}

        def run_command(key, chan, cmd):
            chan.send(f"{cmd}\n")
            outputs[key] = _read_until_idle(chan)

        t1 = threading.Thread(target=run_command, args=("A", chan_a, "echo marker-A"))
        t2 = threading.Thread(target=run_command, args=("B", chan_b, "echo marker-B"))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        client_a.close()
        client_b.close()

        assert "marker-A" in outputs["A"]
        assert "marker-B" in outputs["B"]

        deadline = time.time() + 10
        while time.time() < deadline:
            if collection.count_documents({"event": "cowrie.login.success"}) >= 2:
                break
            time.sleep(0.3)

        success_docs = list(collection.find({"event": "cowrie.login.success"}, {"_id": 0}))
        assert len(success_docs) == 2

        sessions = {d["session"] for d in success_docs}
        assert len(sessions) == 2, "both attackers must have distinct Cowrie session ids"

        command_docs = list(collection.find({"event": "cowrie.command.input"}, {"_id": 0}))
        assert len(command_docs) == 2
        command_sessions = {d["session"] for d in command_docs}
        assert command_sessions == sessions, (
            "each attacker's whoami command must be tagged with that same attacker's "
            "own session id, not the other attacker's - proves no cross-session bleed "
            "even when both were sending commands at the same instant"
        )
