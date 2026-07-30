"""
Layer 8 test plan: Performance / load testing. All 3 parts now covered:
concurrent load (TestConcurrentLoad), restart resilience
(TestRestartResilience), log/DB growth rate (TestLogAndDbGrowth).

Concurrent-load part (per user's explicit prioritization, 2026-07-30, ahead
of restart-resilience and log/DB growth): how many simultaneous attacker
connections can the real Cowrie -> notifier/realtime_alert.py -> MongoDB
pipeline absorb before events start lagging or getting dropped.

This measures concurrent FAILED-login throughput, not concurrent
SUCCESSFUL logins. That's a deliberate design choice, not a simplification
for its own sake: Cowrie's AuthRandom backend (honeypot/cowrie-src/src/
cowrie/core/auth.py) lets, at most, ONE username/password combo ever
succeed per source IP for the lifetime of its on-disk state file
(auth_random.json) - every later attempt from that same IP only succeeds
again if it exactly repeats that one recorded combo. Every attacker in a
test like this shares one source IP (this test machine's loopback address),
so "concurrent successful logins" isn't a meaningful scalability metric
here - it measures Cowrie's own single-attacker-per-IP design, not this
project's pipeline. Concurrent FAILED logins have no such ceiling (Cowrie
happily emits a cowrie.login.failed event for every rejected attempt) and
are also the realistic honeypot workload: real internet-facing scanners
overwhelmingly send a handful of failed credential guesses and move on,
which is exactly what /api/brute-force is built to detect.

Safety: reuses the SAME fixtures as the E2E layer (`cowrie_process`,
`e2e_watcher`) - a REAL Cowrie honeypot and a REAL notifier/realtime_alert.py
watcher, but pointed at the isolated "honeypot_e2e_test" MongoDB database
with Telegram mocked (see conftest.py's `e2e_watcher_session`) - never the
production "honeypot" database or a real Telegram chat.

`cowrie_process` (conftest.py) resets Cowrie's own local auth_random.json
state file once, right before starting the Cowrie subprocess for the whole
session - this is the ONLY point where resetting it has any effect:
AuthRandom's `loadvars()` (honeypot/cowrie-src/src/cowrie/core/auth.py)
runs exactly once, in `__init__`, so overwriting the file while Cowrie is
already running doesn't touch its in-memory state at all (an earlier
version of this file tried to reset between concurrency levels mid-session
and it silently did nothing - the tests below don't actually depend on a
truly fresh AuthRandom state per run, they're designed to produce a
meaningful signal regardless of whatever state it's in, see each test's
own docstring/comments for why). Without the conftest.py-level reset, a
stale recorded combo left behind by an earlier test session (this file
included) would make later E2E logins from a different username
permanently fail - the bug that motivated adding it. This only fixes the
CROSS-session case (separate `pytest` invocations, each starting its own
Cowrie subprocess) - see test_suite_howto's documented run commands,
which already never combine this file and test_e2e.py in one invocation.
Running `pytest tests/test_performance.py tests/test_e2e.py` together
would still pollute test_e2e.py's logins with this file's real traffic,
since both would share the one session-scoped `cowrie_process`; don't do
that.

This is intentionally NOT wired into the default test run. It's slower and
noisier than the correctness suites (it opens dozens of real SSH
connections), and its assertions are sanity floors, not strict pass/fail
correctness checks - the interesting output is the printed report per
concurrency level. Run it explicitly, from the parser venv (same one
test_e2e.py uses, for paramiko):

    cd parser && source venv/bin/activate
    cd .. && pytest tests/test_performance.py -v -s

(-s so the per-concurrency-level report lines are visible; without it
pytest swallows stdout on passing tests.)
"""

from __future__ import annotations

import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko
import pytest

from conftest import REPO_ROOT, _REAL_MONGO_CLIENT

pytestmark = pytest.mark.performance


def _attacker_session(index, attempts_per_attacker=3):
    """
    Simulates one automated scanner: opens `attempts_per_attacker` separate
    connections to Cowrie, each with a distinct, guaranteed-wrong
    username/password, then gives up - the dominant real-world honeypot
    traffic pattern (a handful of credential guesses, then the scanner
    moves to the next target). Every attempt uses a unique combo so Cowrie
    never hits its "already tried this combination" short-circuit (auth.py
    line ~231), which would otherwise silently skip incrementing its
    counter without firing a fresh login.failed event.
    """
    t_start = time.time()
    failed = 0
    for attempt in range(attempts_per_attacker):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                "127.0.0.1", port=2222,
                username=f"attacker{index}",
                password=f"wrongpass-{index}-{attempt}",
                timeout=10, allow_agent=False, look_for_keys=False,
            )
            # Extremely unlikely (would require guessing Cowrie's exact
            # recorded combo) - nothing more to do either way.
            client.close()
        except paramiko.AuthenticationException:
            failed += 1
        except Exception as exc:
            return {
                "index": index, "failed": failed, "error": str(exc),
                "duration": time.time() - t_start,
            }
        finally:
            client.close()

    return {"index": index, "failed": failed, "duration": time.time() - t_start}


def _run_concurrent_load(concurrency, collection, attempts_per_attacker=3):
    """Launches `concurrency` attackers at once via a thread pool (each
    sending `attempts_per_attacker` failed logins), then waits for MongoDB
    to stop growing (a short quiet window, not a fixed sleep) before
    reporting final counts. `collection` must already be empty (see
    `e2e_watcher`)."""
    t0 = time.time()

    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(_attacker_session, i, attempts_per_attacker)
            for i in range(concurrency)
        ]
        for future in as_completed(futures):
            results.append(future.result())

    t_all_attacks_done = time.time()
    total_failed_logins_sent = sum(r["failed"] for r in results)

    # Wait for MongoDB to go quiet (no new doc in the last 1s) instead of
    # guessing an exact expected count - Cowrie's own event shape per
    # connection (connect/failed/closed, occasionally success) isn't worth
    # hardcoding here.
    last_count = -1
    quiet_since = None
    deadline = time.time() + 30
    while time.time() < deadline:
        current_count = collection.count_documents({})
        if current_count == last_count:
            if quiet_since is None:
                quiet_since = time.time()
            elif time.time() - quiet_since > 1.0:
                break
        else:
            quiet_since = None
        last_count = current_count
        time.sleep(0.2)
    t_mongo_settled = time.time()

    login_failed_docs = collection.count_documents({"event": "cowrie.login.failed"})

    return {
        "concurrency": concurrency,
        "attackers_with_errors": sum(1 for r in results if "error" in r),
        "attack_wall_time": t_all_attacks_done - t0,
        "mongo_settle_lag": t_mongo_settled - t_all_attacks_done,
        "total_failed_logins_sent": total_failed_logins_sent,
        "login_failed_docs_in_mongo": login_failed_docs,
        "docs_inserted": last_count,
    }


class TestConcurrentLoad:
    @pytest.mark.parametrize("concurrency", [5, 10, 20])
    def test_perf01_concurrent_failed_login_throughput(self, concurrency, e2e_watcher):
        """
        Ramps up simulated concurrent attacker connections against the real
        Cowrie honeypot, each sending a burst of failed login attempts, and
        measures how the downstream notifier/realtime_alert.py -> MongoDB
        pipeline holds up. Not a strict-timing correctness test (timings
        are hardware-dependent) - it prints one report line per
        concurrency level; the sanity-floor assert below just catches a
        total pipeline collapse (events sent but never showing up at all).
        """
        _, mock_send_message, collection = e2e_watcher

        report = _run_concurrent_load(concurrency, collection)

        print(
            f"\n[perf] concurrency={report['concurrency']:>3} "
            f"attack_wall_time={report['attack_wall_time']:.2f}s "
            f"mongo_settle_lag={report['mongo_settle_lag']:.2f}s "
            f"failed_logins_sent={report['total_failed_logins_sent']} "
            f"login_failed_docs_in_mongo={report['login_failed_docs_in_mongo']} "
            f"docs_inserted_total={report['docs_inserted']} "
            f"attackers_with_errors={report['attackers_with_errors']} "
            f"telegram_alerts_dispatched={mock_send_message.call_count}"
        )

        # Sanity floor, not a strict SLA: essentially every failed login
        # sent should show up as a cowrie.login.failed document. Some slack
        # (90%) for the rare attempt that happens to hit Cowrie's
        # "already tried"/recorded-success edge cases (see module
        # docstring) rather than cleanly failing.
        assert report["login_failed_docs_in_mongo"] >= report["total_failed_logins_sent"] * 0.9, (
            f"only {report['login_failed_docs_in_mongo']} of "
            f"{report['total_failed_logins_sent']} failed logins made it into MongoDB - "
            "the pipeline is dropping events under this concurrency level"
        )


# ---------------------------------------------------------------------------
# Restart resilience
# ---------------------------------------------------------------------------
RESTART_TEST_DB_NAME = "honeypot_restart_perf_test"


def _send_login_probe(username, password="definitely-wrong-password"):
    """One connect + one failed (or, rarely, successful - doesn't matter
    which for this test) login against the real Cowrie honeypot, then
    disconnect. Minimal traffic generator - doesn't run any shell commands."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1", port=2222, username=username, password=password,
            timeout=10, allow_agent=False, look_for_keys=False,
        )
    except paramiko.AuthenticationException:
        pass
    finally:
        client.close()


class TestRestartResilience:
    """
    Kills and restarts the real parser/log_watcher.py mid-stream against the
    real Cowrie honeypot, to measure what a service restart actually costs
    in practice - not just "does it come back up" (already covered
    indirectly by start.sh/healthcheck.sh's pkill+respawn loop in
    production) but "what happens to events that arrive during the
    downtime window".

    Uses parser/log_watcher.py specifically, not notifier/realtime_alert.py:
    log_watcher.py makes NO outbound network calls at all (no Telegram, no
    AbuseIPDB/ipinfo.io - only local Cowrie-log + local GeoIP .mmdb reads
    and MongoDB writes), so it's safe to run as a REAL OS subprocess
    (killable with a real signal, unlike a Python thread) with zero risk of
    ever hitting a real third-party API or sending a real Telegram message.
    Pointed at its own isolated MongoDB database (dropped at the end of the
    test), tailing the real Cowrie log via the `cowrie_process` fixture.
    """

    def test_perf02_events_during_downtime_are_lost_but_recovery_works(self, cowrie_process):
        real_client = _REAL_MONGO_CLIENT("mongodb://localhost:27017")
        real_client.drop_database(RESTART_TEST_DB_NAME)
        collection = real_client[RESTART_TEST_DB_NAME]["attacks"]

        parser_dir = REPO_ROOT / "parser"
        env = os.environ.copy()
        env["MONGO_URL"] = "mongodb://localhost:27017"
        env["DB_NAME"] = RESTART_TEST_DB_NAME

        def _start_watcher():
            return subprocess.Popen(
                [str(parser_dir / "venv" / "bin" / "python3"), "log_watcher.py"],
                cwd=str(parser_dir), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

        def _stop_watcher(proc):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

        def _count(prefix):
            # session.connect/command.input/session.closed docs have no
            # "username" field (None) so this regex only ever matches the
            # one login.failed/login.success doc a probe produces - a
            # clean 1 doc-per-probe signal regardless of which outcome
            # Cowrie's AuthRandom happened to give that attempt.
            return collection.count_documents({"username": {"$regex": f"^{prefix}"}})

        proc = _start_watcher()
        time.sleep(2)  # let it import, open, and seek(0, 2) the real log file

        try:
            # Batch A: watcher is up - should all land in Mongo normally.
            for i in range(3):
                _send_login_probe(f"restartA{i}")
            deadline = time.time() + 10
            while time.time() < deadline and _count("restartA") < 3:
                time.sleep(0.2)
            batch_a_landed = _count("restartA")

            _stop_watcher(proc)  # simulates a crash / manual restart

            # Batch B: generated while NOTHING is tailing the log - these
            # lines land on disk but no process is reading them.
            for i in range(3):
                _send_login_probe(f"restartB{i}")
            time.sleep(1)  # give Cowrie a moment to actually flush the lines

            # Restart: a FRESH process seek(0, 2)s to the file's CURRENT
            # end, so batch B's already-on-disk lines are skipped, not
            # replayed - there is no persistent read-offset/cursor.
            proc = _start_watcher()
            time.sleep(2)
            batch_b_landed = _count("restartB")

            # Batch C: generated after the new process is up - proves
            # forward processing resumes normally post-restart.
            for i in range(3):
                _send_login_probe(f"restartC{i}")
            deadline = time.time() + 10
            while time.time() < deadline and _count("restartC") < 3:
                time.sleep(0.2)
            batch_c_landed = _count("restartC")
        finally:
            _stop_watcher(proc)
            real_client.drop_database(RESTART_TEST_DB_NAME)
            real_client.close()

        print(
            f"\n[perf] restart-resilience: "
            f"batch A (watcher healthy) landed {batch_a_landed}/3 | "
            f"batch B (sent during downtime) landed {batch_b_landed}/3 | "
            f"batch C (sent after restart) landed {batch_c_landed}/3"
        )
        if batch_b_landed > 0:
            print(
                f"[perf] NOTE: {batch_b_landed}/3 downtime-window events unexpectedly "
                "survived - worth investigating further"
            )

        assert batch_a_landed == 3, "watcher failed to ingest events while healthy - unrelated bug"
        assert batch_c_landed == 3, "watcher did not resume ingesting events after restart"
        # batch_b_landed == 0 is NOT asserted as a correctness requirement:
        # it's the documented finding of this test (no persistent read
        # offset -> events during downtime are silently lost), not a bug to
        # fail the build over. See the module/class docstrings.


# ---------------------------------------------------------------------------
# Log / DB growth rate
# ---------------------------------------------------------------------------
class TestLogAndDbGrowth:
    """
    Read-only measurement, no honeypot traffic generated: reads the REAL
    production "honeypot" MongoDB database's collStats (count/avgObjSize/
    size - a read-only command, no writes) and, if present, samples real
    lines from the real Cowrie JSON log, to estimate current bytes-per-event
    and project growth at a few illustrative daily-attack-volume scenarios
    against the current 30-day retention window (parser/cleanup.py).

    Doesn't need `cowrie_process`/`e2e_watcher` - no live Cowrie/watcher
    required, this only reads what's already on disk/in Mongo.

    Deliberately hardcodes "honeypot" rather than reading MONGO_URL/DB_NAME
    from the environment: conftest.py's `e2e_watcher_session` fixture sets
    os.environ["DB_NAME"] = "honeypot_e2e_test" process-wide and never
    restores it, so if this test runs later in the same pytest session
    (e.g. after TestConcurrentLoad/TestRestartResilience), os.getenv
    would silently return the leftover E2E test database's name instead
    of the real production database this test is supposed to read -
    exactly the bug that produced a wildly-wrong doc count the first time
    this test was written and run.
    """

    def test_perf03_estimates_log_and_db_growth_rate(self):
        real_client = _REAL_MONGO_CLIENT("mongodb://localhost:27017")
        db = real_client["honeypot"]

        try:
            stats = db.command("collStats", "attacks")
        except Exception as exc:
            real_client.close()
            pytest.skip(f"could not read collStats on the real 'honeypot' db: {exc}")

        doc_count = stats.get("count", 0)
        avg_obj_size = stats.get("avgObjSize", 0) or 0
        total_size = stats.get("size", 0)
        real_client.close()

        log_path = (
            REPO_ROOT / "honeypot" / "cowrie-src" / "var" / "log" / "cowrie" / "cowrie.json"
        )
        avg_log_line_bytes = None
        sample_lines = 0
        if log_path.exists():
            with open(log_path, "rb") as f:
                lines = f.readlines()[-500:]
            if lines:
                sample_lines = len(lines)
                avg_log_line_bytes = sum(len(line) for line in lines) / sample_lines

        print(
            f"\n[perf] production honeypot.attacks: {doc_count} docs, "
            f"avg {avg_obj_size:.0f} bytes/doc, {total_size} bytes total"
        )
        if avg_log_line_bytes:
            print(
                f"[perf] real cowrie.json: avg {avg_log_line_bytes:.0f} bytes/line "
                f"(last {sample_lines} lines sampled)"
            )
        else:
            print("[perf] real cowrie.json not found on this machine - skipping raw-log estimate")

        # Rough estimate, not a precise capacity-planning number: a simple
        # automated-scanner attack (connect + a few failed logins + closed)
        # produces roughly 3-5 Mongo docs; an interactive attacker session
        # that runs commands produces one extra doc per command, which can
        # dominate the total for a persistent human/bot attacker. 4 is a
        # reasonable floor for the common "scan and move on" case this
        # project's traffic is mostly made of (see the 31 real docs so far).
        events_per_attack_estimate = 4
        bytes_per_doc = avg_obj_size or 300  # fallback guess if collection is empty
        print(
            "\n[perf] Projected MongoDB 'attacks' collection growth at illustrative "
            f"daily attack volumes (~{events_per_attack_estimate} docs/attack, "
            f"~{bytes_per_doc:.0f} bytes/doc):"
        )
        for attacks_per_day in (100, 500, 2000, 10000):
            docs_per_day = attacks_per_day * events_per_attack_estimate
            bytes_per_day = docs_per_day * bytes_per_doc
            bytes_30_days = bytes_per_day * 30
            print(
                f"  {attacks_per_day:>6} attacks/day -> "
                f"{docs_per_day:>7} docs/day -> "
                f"{bytes_per_day / 1024 / 1024:>7.2f} MB/day -> "
                f"{bytes_30_days / 1024 / 1024 / 1024:>6.2f} GB over the current "
                "30-day retention window"
            )

        assert doc_count >= 0 and avg_obj_size >= 0  # sanity: collStats returned something sane
