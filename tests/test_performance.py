"""
Layer 8 test plan: Performance / load testing.

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
production "honeypot" database or a real Telegram chat. Also resets Cowrie's
own local auth_random.json state file before each run (see
`_reset_cowrie_auth_state` below) - this is the honeypot's own scratch
state on this machine, not application data, and resetting it makes each
concurrency level start from the same "first visit" baseline instead of
being at the mercy of whatever an earlier run (or an earlier E2E test)
happened to leave behind.

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

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import paramiko
import pytest

from conftest import REPO_ROOT

pytestmark = pytest.mark.performance

AUTH_RANDOM_STATE_FILE = (
    REPO_ROOT / "honeypot" / "cowrie-src" / "var" / "lib" / "cowrie" / "auth_random.json"
)


def _reset_cowrie_auth_state():
    """Clears Cowrie's own AuthRandom state file so 127.0.0.1 starts each
    concurrency level as a fresh "first visit" IP - see module docstring
    for why a stale recorded combo from an earlier run would otherwise
    make every different-username attempt fail for the rest of this file's
    lifetime. This is the honeypot's local scratch state, not app data."""
    AUTH_RANDOM_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_RANDOM_STATE_FILE.write_text(json.dumps({}))


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
    _reset_cowrie_auth_state()
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
