"""
Shared pytest fixtures for the Honeypot-Monitor test suite.

Two session-wide safety nets are enforced for every test in this suite,
regardless of what any individual test remembers to mock:

1. `_never_touch_real_mongo` - parser/log_watcher.py, parser/parser.py,
   parser/cleanup.py, and notifier/{realtime_alert,telegram_commands}.py
   all do `MongoClient("mongodb://localhost:27017")` at import time,
   pointed at the real "honeypot" database the running honeypot writes
   production attacker data into. Always import these via the
   `fresh_module` fixture (never `import log_watcher` at the top of a
   test file) so that resolves to an isolated in-memory mongomock
   instance instead.

2. `_never_make_real_http_requests` - notifier/.env holds real Telegram
   bot and AbuseIPDB credentials. requests.post/requests.get are replaced
   with a function that raises loudly instead of silently sending a real
   Telegram message (or leaking the real token in a network call) if a
   test forgets to mock them.
"""

from __future__ import annotations

import importlib
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _dir_name in ("parser", "notifier"):
    _dir = REPO_ROOT / _dir_name
    if str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))

# Captured at module import time, before `_never_touch_real_mongo` below
# patches pymongo.MongoClient for the rest of the session. `live_stack`
# needs a REAL client to drop the isolated test database it created on
# teardown - going through the (by then patched) `pymongo.MongoClient`
# name would silently operate on a throwaway mongomock instance instead.
import pymongo as _pymongo_module

_REAL_MONGO_CLIENT = _pymongo_module.MongoClient


@pytest.fixture(autouse=True, scope="session")
def _never_touch_real_mongo():
    """
    Session-wide safety net: replace pymongo.MongoClient with mongomock's
    BEFORE any parser module is (re-)imported, for the entire test run.

    This is deliberately global rather than scoped to individual tests -
    even a test author who forgets to use the `fresh_module` fixture below
    still can't accidentally open a connection to the real MongoDB the
    honeypot depends on, because there simply is no real MongoClient
    available anywhere during this pytest session.
    """
    import mongomock
    import pymongo

    original = pymongo.MongoClient
    pymongo.MongoClient = mongomock.MongoClient
    try:
        yield
    finally:
        pymongo.MongoClient = original


def _make_poison(method_name: str):
    def _poison(*args, **kwargs):
        raise RuntimeError(
            f"A test attempted a REAL requests.{method_name}(...) call "
            f"instead of mocking it - args={args!r} kwargs={kwargs!r}. "
            "This would hit a real network endpoint using the real "
            "credentials in notifier/.env."
        )

    return _poison


@pytest.fixture(autouse=True, scope="session")
def _never_make_real_http_requests():
    """
    Session-wide safety net: replace requests.post/requests.get with a
    poison pill for the entire test run. Individual tests override this
    per-test with `monkeypatch.setattr(requests, "post", Mock(...))`,
    which correctly saves/restores around the poison pill.
    """
    import requests

    original_post, original_get = requests.post, requests.get
    requests.post = _make_poison("post")
    requests.get = _make_poison("get")
    try:
        yield
    finally:
        requests.post = original_post
        requests.get = original_get


@pytest.fixture
def fresh_module():
    """
    Import one of parser/{log_watcher,parser,cleanup,geoip_lookup}.py fresh,
    bypassing Python's sys.modules cache, so its module-level
    `client = MongoClient(...)` line runs again and produces a brand-new,
    empty mongomock instance private to this one test. Because mongomock
    gives each MongoClient() call its own isolated in-memory store, this
    also means tests never leak documents into each other - no manual
    `collection.delete_many({})` cleanup needed between tests.

    Usage:
        def test_x(fresh_module):
            log_watcher = fresh_module("log_watcher")
            doc = log_watcher.parse_event({...})
    """
    imported_names: list[str] = []

    def _import(name: str):
        sys.modules.pop(name, None)
        module = importlib.import_module(name)
        imported_names.append(name)
        return module

    yield _import

    for name in imported_names:
        sys.modules.pop(name, None)


@pytest.fixture
def fresh_app(monkeypatch, fresh_module):
    """
    Import parser/main.py (and, transitively, parser/auth.py that it does
    `import auth` for) fresh, with a throwaway JWT secret and mongomock
    collections, wrapped in a Starlette TestClient.

    main.py's `attacks` collection and auth.py's `users` /
    `refresh_tokens` / `login_attempts` / `auth_log` collections are all
    separate mongomock instances - auth.py must be re-imported together
    with main.py (not left cached from an earlier test), or a test would
    silently share another test's session/lockout state.

    Returns (client, main_module, auth_module).
    """
    from fastapi.testclient import TestClient

    monkeypatch.setenv("JWT_SECRET_KEY", "test-only-secret-" + "x" * 32)
    monkeypatch.setenv("DASHBOARD_ORIGIN", "http://localhost:8080")

    sys.modules.pop("auth", None)
    main = fresh_module("main")

    return TestClient(main.app), main, main.auth


TEST_API_PORT = 18000
TEST_DASHBOARD_PORT = 18080
TEST_DB_NAME = "honeypot_test"


@pytest.fixture(scope="session")
def live_stack():
    """
    Launches a REAL uvicorn (parser/main.py) and a REAL live-server
    (dashboard/) as subprocesses, for the Dashboard layer's Playwright
    tests, which need actual HTTP/cookie/CORS/JS behaviour in a real
    browser that TestClient can't fully replicate.

    Safety: both processes are launched with MONGO_URL/DB_NAME pointed at
    an isolated "honeypot_test" database on the same real mongod - never
    "honeypot", the production database the honeypot writes to. The test
    database is dropped entirely on teardown. This relies on main.py and
    auth.py reading MONGO_URL/DB_NAME from the environment (confirmed with
    the user before adding this fixture - see the commit/conversation
    history for that change).

    Ports 18000/18080 are deliberately not 8000/8080 so this never
    collides with a real start.sh-launched stack running on the same
    machine.
    """
    import os
    import subprocess

    import httpx

    env = os.environ.copy()
    env["MONGO_URL"] = "mongodb://localhost:27017"
    env["DB_NAME"] = TEST_DB_NAME
    env["JWT_SECRET_KEY"] = "dashboard-layer-test-secret-" + "x" * 32
    env["DASHBOARD_ORIGIN"] = f"http://localhost:{TEST_DASHBOARD_PORT}"

    parser_dir = REPO_ROOT / "parser"
    dashboard_dir = REPO_ROOT / "dashboard"
    # "localhost" everywhere, deliberately not mixed with 127.0.0.1 - the
    # browser treats those as different origins, and the CORS middleware
    # only allows the exact DASHBOARD_ORIGIN string set below.
    api_url = f"http://localhost:{TEST_API_PORT}"
    dashboard_url = f"http://localhost:{TEST_DASHBOARD_PORT}"

    api_proc = subprocess.Popen(
        [
            str(parser_dir / "venv" / "bin" / "python3"),
            "-m", "uvicorn", "main:app",
            "--host", "127.0.0.1", "--port", str(TEST_API_PORT),
        ],
        cwd=str(parser_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dashboard_proc = subprocess.Popen(
        ["live-server", ".", f"--port={TEST_DASHBOARD_PORT}", "--host=127.0.0.1", "--no-browser"],
        cwd=str(dashboard_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def _wait_for_http(url, timeout=15):
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                httpx.get(url, timeout=1)
                return
            except Exception as e:
                last_error = e
                time.sleep(0.3)
        raise RuntimeError(f"server at {url} did not become ready in time: {last_error}")

    real_client = _REAL_MONGO_CLIENT("mongodb://localhost:27017")
    test_db = real_client[TEST_DB_NAME]

    try:
        _wait_for_http(f"{api_url}/")
        _wait_for_http(f"{dashboard_url}/login.html")
        yield api_url, dashboard_url, test_db
    finally:
        api_proc.terminate()
        dashboard_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()
        try:
            dashboard_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dashboard_proc.kill()

        real_client.drop_database(TEST_DB_NAME)
        real_client.close()


@pytest.fixture
def live_stack_clean(live_stack):
    """Same as `live_stack`, but drops every collection in the isolated
    test database before the test runs, so tests that seed their own data
    don't see leftovers from an earlier test in the same session (the API
    server subprocess is session-scoped and shared across all Dashboard
    tests, unlike the mongomock-per-test isolation the other layers get)."""
    api_url, dashboard_url, test_db = live_stack
    for name in test_db.list_collection_names():
        test_db[name].delete_many({})
    return api_url, dashboard_url, test_db


# ---------------------------------------------------------------------------
# Layer 7 (E2E): a REAL Cowrie honeypot + the REAL notifier/realtime_alert.py
# watcher, with Telegram mocked (per the user's explicit choice not to send
# real Telegram messages from an automated test) and MongoDB pointed at an
# isolated database.
# ---------------------------------------------------------------------------

E2E_DB_NAME = "honeypot_e2e_test"
COWRIE_SSH_PORT = 2222


@pytest.fixture(scope="session")
def cowrie_process():
    """
    Starts the REAL Cowrie honeypot (SSH on :2222) as a subprocess for the
    E2E layer - this is the actual production honeypot under test, not a
    mock. `cowrie start` auto-cleans a stale PID file if the previous run
    didn't shut down cleanly (see cowrie/scripts/cowrie.py). Stopped via
    `cowrie force-stop` (waits for graceful shutdown, then SIGKILLs) on
    teardown.
    """
    import json
    import os
    import socket
    import subprocess

    cowrie_dir = REPO_ROOT / "honeypot" / "cowrie-src"
    cowrie_env_bin = cowrie_dir / "cowrie-env" / "bin"
    cowrie_bin = cowrie_env_bin / "cowrie"

    # Reset Cowrie's own AuthRandom state (honeypot/cowrie-src/src/cowrie/
    # core/auth.py) BEFORE starting it - that class loads this file once
    # into memory at process startup, so resetting it after Cowrie is
    # already running wouldn't take effect. Without this, a stale recorded
    # username/password combo for 127.0.0.1 left behind by an EARLIER test
    # session (e.g. test_performance.py's restart-resilience test uses
    # "restartA0"/etc as usernames) permanently blocks every later
    # session's E2E logins using a different username ("root") - this is
    # what actually caused test_e2e.py's real failures, not a missing
    # ipinfo.io mock (that exception is already caught gracefully inside
    # bot.py's get_ip_info() and was a red herring in the logs).
    auth_random_state_file = cowrie_dir / "var" / "lib" / "cowrie" / "auth_random.json"
    auth_random_state_file.parent.mkdir(parents=True, exist_ok=True)
    auth_random_state_file.write_text(json.dumps({}))

    # `cowrie start` execs `twistd` via os.execvp, which searches PATH -
    # cowrie-env/bin must be on it (normally done by `source
    # cowrie-env/bin/activate`), or it fails with FileNotFoundError.
    env = os.environ.copy()
    env["PATH"] = f"{cowrie_env_bin}{os.pathsep}{env.get('PATH', '')}"

    subprocess.run(
        [str(cowrie_bin), "start"],
        cwd=str(cowrie_dir),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    def _port_open(host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex((host, port)) == 0

    deadline = time.time() + 20
    while time.time() < deadline:
        if _port_open("127.0.0.1", COWRIE_SSH_PORT):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("Cowrie did not start listening on port 2222 in time")

    try:
        yield
    finally:
        subprocess.run(
            [str(cowrie_bin), "force-stop"],
            cwd=str(cowrie_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=70,
        )
        real_client = _REAL_MONGO_CLIENT("mongodb://localhost:27017")
        real_client.drop_database(E2E_DB_NAME)
        real_client.close()


E2E_API_PORT = 18001
E2E_DASHBOARD_PORT = 18081


@pytest.fixture(scope="session")
def e2e_dashboard_stack(cowrie_process):
    """
    Real uvicorn + live-server for the E2E layer, pointed at the SAME
    isolated "honeypot_e2e_test" database the `e2e_watcher` fixture's
    in-process watcher writes to. Lets E2E tests close the loop with a
    real browser actually seeing a real attack show up on the dashboard,
    not just verifying MongoDB state - separate ports from the Dashboard
    layer's own `live_stack` so both could run in the same session
    without colliding.
    """
    import os
    import subprocess

    import httpx

    env = os.environ.copy()
    env["MONGO_URL"] = "mongodb://localhost:27017"
    env["DB_NAME"] = E2E_DB_NAME
    env["JWT_SECRET_KEY"] = "e2e-layer-test-secret-" + "x" * 32
    env["DASHBOARD_ORIGIN"] = f"http://localhost:{E2E_DASHBOARD_PORT}"

    parser_dir = REPO_ROOT / "parser"
    dashboard_dir = REPO_ROOT / "dashboard"
    api_url = f"http://localhost:{E2E_API_PORT}"
    dashboard_url = f"http://localhost:{E2E_DASHBOARD_PORT}"

    api_proc = subprocess.Popen(
        [
            str(parser_dir / "venv" / "bin" / "python3"),
            "-m", "uvicorn", "main:app",
            "--host", "127.0.0.1", "--port", str(E2E_API_PORT),
        ],
        cwd=str(parser_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dashboard_proc = subprocess.Popen(
        ["live-server", ".", f"--port={E2E_DASHBOARD_PORT}", "--host=127.0.0.1", "--no-browser"],
        cwd=str(dashboard_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def _wait_for_http(url, timeout=15):
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                httpx.get(url, timeout=1)
                return
            except Exception as e:
                last_error = e
                time.sleep(0.3)
        raise RuntimeError(f"server at {url} did not become ready in time: {last_error}")

    try:
        _wait_for_http(f"{api_url}/")
        _wait_for_http(f"{dashboard_url}/login.html")
        yield api_url, dashboard_url
    finally:
        api_proc.terminate()
        dashboard_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()
        try:
            dashboard_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dashboard_proc.kill()


@pytest.fixture(scope="session")
def e2e_watcher_session(cowrie_process):
    """
    Runs the REAL notifier/realtime_alert.py watch_log() loop in a
    background thread inside this pytest process (not a subprocess), so
    bot.send_message can be safely mocked - launching it as a real
    subprocess would use the real Telegram credentials in notifier/.env,
    which the user explicitly chose to avoid for automated E2E runs.

    Session-scoped deliberately: watch_log() has no clean shutdown
    mechanism (it's an unconditional `while True`), so starting a fresh
    thread per test would leave earlier tests' threads still tailing the
    same real Cowrie log file forever, causing duplicate inserts once a
    later test's traffic gets appended. One thread for the whole session;
    use `e2e_watcher` (function-scoped) to reset state between tests.

    Points MONGO_URL/DB_NAME at an isolated "honeypot_e2e_test" database
    (dropped at session end via `cowrie_process`'s teardown) on the real
    mongod. LOG_FILE is left as realtime_alert.py's own default - the real
    path `cowrie_process`'s Cowrie instance writes to. REALTIME_ALERT_OFFSET_FILE
    is pointed at a throwaway temp path, NOT realtime_alert.py's own default
    (which would land in the real repo's logs/ directory) - otherwise this
    session would save a real inode/byte-position against the real Cowrie
    log file, which a later NATIVE (non-test) run of realtime_alert.py
    against that same log could inherit and skip ahead past real events.

    Note: this module MUST get a real, persistent MongoClient, not the
    mongomock `_never_touch_real_mongo` patches in for the rest of the
    session - it needs to share actual state with the separate
    `e2e_dashboard_stack` API subprocess, which has its own real
    MongoClient in a different OS process entirely.
    """
    import os
    import tempfile
    from unittest.mock import Mock

    os.environ["MONGO_URL"] = "mongodb://localhost:27017"
    os.environ["DB_NAME"] = E2E_DB_NAME
    os.environ["REALTIME_ALERT_OFFSET_FILE"] = os.path.join(
        tempfile.mkdtemp(prefix="e2e-realtime-alert-offset-"), "realtime_alert.offset.json"
    )

    sys.modules.pop("bot", None)
    sys.modules.pop("realtime_alert", None)

    original_mongo_client = _pymongo_module.MongoClient
    _pymongo_module.MongoClient = _REAL_MONGO_CLIENT
    try:
        bot = importlib.import_module("bot")
        realtime_alert = importlib.import_module("realtime_alert")
    finally:
        _pymongo_module.MongoClient = original_mongo_client

    mock_send_message = Mock(return_value=True)
    bot.send_message = mock_send_message
    realtime_alert.collection.delete_many({})

    thread = threading.Thread(target=realtime_alert.watch_log, daemon=True)
    thread.start()
    time.sleep(0.5)  # let it open + seek(0, 2) the real log file first

    yield realtime_alert, mock_send_message, realtime_alert.collection

    sys.modules.pop("bot", None)
    sys.modules.pop("realtime_alert", None)


@pytest.fixture
def e2e_watcher(e2e_watcher_session):
    """Per-test view of the session-wide watcher: clears the attacks
    collection and the mock's call history so each test starts from a
    clean slate, without restarting the (unstoppable) watcher thread."""
    realtime_alert, mock_send_message, collection = e2e_watcher_session
    collection.delete_many({})
    mock_send_message.reset_mock()
    return realtime_alert, mock_send_message, collection


def wait_until(condition, timeout=3.0, interval=0.05, message="condition not met"):
    """
    Poll `condition()` until it returns truthy or `timeout` seconds pass.
    Used instead of a fixed sleep() when a test hands work to a background
    thread (e.g. log_watcher.watch_log() tailing a file) - avoids both
    flakiness (sleeping too little) and slow tests (sleeping too long).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return
        time.sleep(interval)
    raise AssertionError(message)


# ---------------------------------------------------------------------------
# Raw Cowrie event factories - field names/shape match the real JSON lines
# produced by Cowrie (verified against honeypot/sample_log.json), so tests
# read close to real log data instead of ad-hoc dicts invented per test.
# ---------------------------------------------------------------------------


def make_connect_event(session="sess001", src_ip="203.0.113.7", src_port=51234,
                        dst_port=2222, **overrides):
    event = {
        "eventid": "cowrie.session.connect",
        "session": session,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": "10.0.0.15",
        "dst_port": dst_port,
        "sensor": "honeypot-01",
        "timestamp": "2026-04-12T11:39:40.335530Z",
    }
    event.update(overrides)
    return event


def make_client_version_event(session="sess001", version="SSH-2.0-OpenSSH_for_Windows_8.1",
                               **overrides):
    event = {
        "eventid": "cowrie.client.version",
        "session": session,
        "version": version,
        "sensor": "honeypot-01",
        "timestamp": "2026-04-12T11:39:40.336Z",
    }
    event.update(overrides)
    return event


def make_kex_event(session="sess001", hassh="ec7378c1a92f5a8dde7e8b7a1ddf33d1",
                    hassh_algorithms="curve25519-sha256;aes128-ctr;hmac-sha2-256;none",
                    **overrides):
    event = {
        "eventid": "cowrie.client.kex",
        "session": session,
        "hassh": hassh,
        "hasshAlgorithms": hassh_algorithms,
        "sensor": "honeypot-01",
        "timestamp": "2026-04-12T11:39:40.400Z",
    }
    event.update(overrides)
    return event


def make_login_failed_event(session="sess001", src_ip="203.0.113.7",
                             username="root", password="123456", **overrides):
    event = {
        "eventid": "cowrie.login.failed",
        "session": session,
        "src_ip": src_ip,
        "username": username,
        "password": password,
        "sensor": "honeypot-01",
        "timestamp": "2026-04-12T11:39:41.000Z",
    }
    event.update(overrides)
    return event


def make_login_success_event(session="sess001", src_ip="203.0.113.7",
                              username="root", password="toor", **overrides):
    event = {
        "eventid": "cowrie.login.success",
        "session": session,
        "src_ip": src_ip,
        "username": username,
        "password": password,
        "sensor": "honeypot-01",
        "timestamp": "2026-04-12T11:39:42.000Z",
    }
    event.update(overrides)
    return event


def make_command_event(session="sess001", src_ip="203.0.113.7",
                        command="whoami", **overrides):
    event = {
        "eventid": "cowrie.command.input",
        "session": session,
        "src_ip": src_ip,
        "input": command,
        "sensor": "honeypot-01",
        "timestamp": "2026-04-12T11:39:43.000Z",
    }
    event.update(overrides)
    return event


def make_closed_event(session="sess001", duration="212.6", **overrides):
    event = {
        "eventid": "cowrie.session.closed",
        "session": session,
        "duration": duration,
        "sensor": "honeypot-01",
        "timestamp": "2026-04-12T11:43:14.000Z",
    }
    event.update(overrides)
    return event
