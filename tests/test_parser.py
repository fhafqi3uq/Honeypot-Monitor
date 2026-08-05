"""
Layer 2 test plan: Parser / Log processing (PL-01 .. PL-14 from the test
plan table).

Every test goes through the `fresh_module` fixture (see conftest.py) so
parser/log_watcher.py, parser/parser.py, parser/geoip_lookup.py, and
parser/cleanup.py all run against an isolated in-memory mongomock instance
- none of them ever touch the real "honeypot" MongoDB database.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from conftest import (
    make_client_version_event,
    make_closed_event,
    make_command_event,
    make_connect_event,
    make_kex_event,
    make_login_failed_event,
    make_login_success_event,
    wait_until,
)


# ---------------------------------------------------------------------------
# PL-01, PL-02, PL-03, PL-04, PL-08, PL-09
# Pure parse_event()/update_session_cache() logic - fast, no file I/O.
#
# Parametrized over BOTH log_watcher.py and parser.py: they hand-duplicate
# the same parsing logic (per CLAUDE.md's own warning that nothing shares
# this code between the two files), so running every case against both
# modules automatically catches the two implementations drifting apart.
# ---------------------------------------------------------------------------
class TestParseEventCore:
    @pytest.fixture(params=["log_watcher", "parser"])
    def target(self, request, fresh_module):
        return fresh_module(request.param)

    def test_pl01_parses_basic_fields(self, target):
        raw = make_login_failed_event(src_ip="203.0.113.7", username="root", password="123456")
        doc = target.parse_event(raw)

        assert doc is not None
        assert doc["event"] == "cowrie.login.failed"
        assert doc["src_ip"] == "203.0.113.7"
        assert doc["username"] == "root"
        assert doc["password"] == "123456"
        assert doc["session"] == "sess001"
        assert doc["sensor"] == "honeypot-01"
        assert doc["timestamp"] == raw["timestamp"]
        assert doc["alerted"] is False
        assert "created_at" in doc

    def test_pl02_session_cache_enriches_later_events(self, target):
        target.update_session_cache(make_connect_event(src_port=51234, dst_port=2222))
        target.update_session_cache(
            make_client_version_event(version="SSH-2.0-OpenSSH_for_Windows_8.1")
        )
        target.update_session_cache(make_kex_event(hassh="ec7378c1a92f5a8dde7e8b7a1ddf33d1"))

        doc = target.parse_event(make_login_failed_event())

        assert doc["src_port"] == 51234
        assert doc["dst_port"] == 2222
        assert doc["client_version"] == "SSH-2.0-OpenSSH_for_Windows_8.1"
        assert doc["hassh"] == "ec7378c1a92f5a8dde7e8b7a1ddf33d1"

    def test_pl02_missing_cache_leaves_enrichment_fields_none(self, target):
        # No connect/version/kex event was ever seen for this session.
        doc = target.parse_event(make_login_failed_event(session="never-seen-before"))

        assert doc["src_port"] is None
        assert doc["client_version"] is None
        assert doc["hassh"] is None

    def test_pl03_duration_only_present_on_session_closed(self, target):
        connect_doc = target.parse_event(make_connect_event())
        failed_doc = target.parse_event(make_login_failed_event())
        closed_doc = target.parse_event(make_closed_event(duration="212.6"))

        assert connect_doc["duration"] is None
        assert failed_doc["duration"] is None
        assert closed_doc["duration"] == "212.6"

    def test_pl04_session_cache_cleared_after_close(self, target):
        target.update_session_cache(make_connect_event(session="sessX"))
        assert "sessX" in target.SESSION_CACHE

        target.parse_event(make_closed_event(session="sessX"))

        assert "sessX" not in target.SESSION_CACHE

    def test_pl08_duplicate_events_are_not_deduplicated(self, target):
        """Pins down CURRENT behaviour: there is no content-based dedup
        anywhere in this pipeline. Sending the exact same failed-login line
        twice produces two separate documents. If dedup is added later,
        this test should be updated to assert the new behaviour."""
        raw = make_login_failed_event()
        target.collection.insert_one(target.parse_event(raw))
        target.collection.insert_one(target.parse_event(raw))

        assert target.collection.count_documents({"event": "cowrie.login.failed"}) == 2

    def test_pl09_interleaved_sessions_do_not_bleed_fields(self, target):
        target.update_session_cache(make_connect_event(session="A", src_port=1111))
        target.update_session_cache(make_connect_event(session="B", src_port=2222))
        target.update_session_cache(make_kex_event(session="A", hassh="hash-a"))
        target.update_session_cache(make_kex_event(session="B", hassh="hash-b"))

        doc_a = target.parse_event(make_login_failed_event(session="A", username="alice"))
        doc_b = target.parse_event(make_login_failed_event(session="B", username="bob"))

        assert doc_a["src_port"] == 1111
        assert doc_a["hassh"] == "hash-a"
        assert doc_a["username"] == "alice"

        assert doc_b["src_port"] == 2222
        assert doc_b["hassh"] == "hash-b"
        assert doc_b["username"] == "bob"

    def test_events_outside_important_events_return_none(self, target):
        assert target.parse_event(make_client_version_event()) is None
        assert target.parse_event(make_kex_event()) is None


# ---------------------------------------------------------------------------
# PL-05, PL-06, PL-07, PL-10
# These need the real log_watcher.watch_log() tailing loop running against
# an actual file on disk, so they run it in a background daemon thread.
# ---------------------------------------------------------------------------
def _start_watch_log(module, tmp_path):
    """Point module.LOG_FILE at a fresh temp file and start
    module.watch_log() tailing it in a background daemon thread. Returns
    (append_line, log_path)."""
    log_path = tmp_path / "cowrie.json"
    log_path.write_text("")
    module.LOG_FILE = str(log_path)
    # Also isolate the saved-offset file to tmp_path - otherwise every test
    # would read/write the real repo's logs/log_watcher.offset.json, and
    # (harmlessly, since the inode never matches a fresh temp file, but
    # still untidy) leave that file behind after the test run.
    module.OFFSET_FILE = str(tmp_path / "log_watcher.offset.json")

    thread = threading.Thread(target=module.watch_log, daemon=True)
    thread.start()
    # Let watch_log() open the file and seek(0, 2) to EOF before we append,
    # otherwise a line written here could race ahead of that initial seek.
    time.sleep(0.2)

    def append_line(line: str):
        with open(log_path, "a") as f:
            f.write(line + "\n")

    return append_line, log_path


class TestLogWatcherTailing:
    def test_pl05_empty_and_whitespace_lines_are_skipped(self, fresh_module, tmp_path):
        log_watcher = fresh_module("log_watcher")
        append_line, _ = _start_watch_log(log_watcher, tmp_path)

        append_line("")
        append_line("   ")
        append_line(json.dumps(make_login_failed_event(session="s-empty-test")))

        wait_until(
            lambda: log_watcher.collection.count_documents({}) == 1,
            message="expected exactly 1 document - empty/whitespace lines must insert nothing",
        )
        doc = log_watcher.collection.find_one({}, {"_id": 0})
        assert doc["session"] == "s-empty-test"

    def test_pl06_malformed_json_does_not_crash_the_loop(self, fresh_module, tmp_path):
        log_watcher = fresh_module("log_watcher")
        append_line, _ = _start_watch_log(log_watcher, tmp_path)

        append_line('{"eventid": "cowrie.login.failed", "session": "broken"')  # truncated JSON
        append_line(json.dumps(make_login_failed_event(session="s-after-broken")))

        wait_until(
            lambda: log_watcher.collection.count_documents({}) == 1,
            message="watcher should skip the malformed line and still process the next valid one",
        )
        doc = log_watcher.collection.find_one({}, {"_id": 0})
        assert doc["session"] == "s-after-broken"

    def test_pl07_unusual_encoding_in_command_is_preserved(self, fresh_module, tmp_path):
        log_watcher = fresh_module("log_watcher")
        append_line, _ = _start_watch_log(log_watcher, tmp_path)

        weird_command = "cat /etc/passwd; echo 'Xin chào 👋 привет'"
        append_line(json.dumps(make_command_event(command=weird_command), ensure_ascii=False))

        wait_until(lambda: log_watcher.collection.count_documents({}) == 1)
        doc = log_watcher.collection.find_one({}, {"_id": 0})
        assert doc["command"] == weird_command

    def test_pl10_log_watcher_survives_log_rotation(self, fresh_module, tmp_path):
        """
        Regression test for a fixed gap: log_watcher.py used to open
        LOG_FILE once and never notice the path had been replaced by a new
        file - which is exactly what Cowrie's `logtype=rotating` does at
        midnight, silently losing every event logged after a rotation
        until the process was restarted. watch_log() now compares
        os.stat().st_ino every poll cycle (same technique
        realtime_alert.py already used) and reopens the path when the
        inode changes.
        """
        log_watcher = fresh_module("log_watcher")
        append_line, log_path = _start_watch_log(log_watcher, tmp_path)

        append_line(json.dumps(make_login_failed_event(session="before-rotation")))
        wait_until(lambda: log_watcher.collection.count_documents({}) == 1)

        # Simulate Cowrie's midnight rotation: the old file is renamed away
        # and a brand-new file is created at the original path.
        rotated_path = log_path.with_suffix(".json.rotated")
        os.rename(log_path, rotated_path)
        log_path.write_text("")
        with open(log_path, "a") as f:
            f.write(json.dumps(make_login_failed_event(session="after-rotation")) + "\n")

        wait_until(
            lambda: log_watcher.collection.count_documents({}) == 2,
            message="log_watcher.py did not pick up the post-rotation event",
        )
        sessions = {doc["session"] for doc in log_watcher.collection.find({}, {"_id": 0})}
        assert sessions == {"before-rotation", "after-rotation"}


# ---------------------------------------------------------------------------
# PL-11, PL-12: geoip_lookup.py
# ---------------------------------------------------------------------------
class TestGeoIPLookup:
    def test_pl11_private_ip_returns_local_without_touching_mmdb(self, fresh_module, monkeypatch):
        geoip_lookup = fresh_module("geoip_lookup")
        # If get_geo() ever tried to open the mmdb for a private IP instead
        # of short-circuiting, pointing DB_PATH at nothing would surface it.
        monkeypatch.setattr(geoip_lookup, "DB_PATH", "/nonexistent/path.mmdb")

        for ip in ["127.0.0.1", "192.168.1.5", "10.0.0.5", "172.16.0.1"]:
            assert geoip_lookup.get_geo(ip) == {
                "country": "Local",
                "country_code": "LO",
                "city": "localhost",
                "latitude": 0.0,
                "longitude": 0.0,
            }

    def test_pl12_missing_mmdb_file_fails_closed_to_unknown(self, fresh_module, monkeypatch):
        geoip_lookup = fresh_module("geoip_lookup")
        monkeypatch.setattr(geoip_lookup, "DB_PATH", "/nonexistent/path.mmdb")

        geo = geoip_lookup.get_geo("8.8.8.8")  # public IP - would normally hit the real mmdb

        assert geo == {
            "country": "Unknown",
            "country_code": "??",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
        }


# ---------------------------------------------------------------------------
# PL-13: cleanup.py
# ---------------------------------------------------------------------------
class TestCleanup:
    def test_pl13_deletes_only_records_older_than_30_days(self, fresh_module):
        cleanup = fresh_module("cleanup")

        old_ts = (datetime.utcnow() - timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%S")
        recent_ts = (datetime.utcnow() - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S")
        cleanup.collection.insert_many(
            [
                {"session": "old", "timestamp": old_ts},
                {"session": "recent", "timestamp": recent_ts},
            ]
        )

        cleanup.cleanup_old_logs()

        remaining = list(cleanup.collection.find({}, {"_id": 0, "session": 1}))
        assert remaining == [{"session": "recent"}]

    def test_pl13b_prunes_old_rotated_cowrie_log_files_only(self, fresh_module, tmp_path, monkeypatch):
        """
        Cowrie itself (logtype = rotating) rotates cowrie.log/cowrie.json to
        a dated suffix every midnight forever with no built-in retention of
        its own - only the Mongo copy was ever pruned. cleanup_old_cowrie_log_files()
        closes that gap: old rotated files get deleted, the live (no date
        suffix) files are never touched regardless of age.
        """
        live_json = tmp_path / "cowrie.json"
        live_log = tmp_path / "cowrie.log"
        old_json = tmp_path / "cowrie.json.2020-01-01"
        old_log = tmp_path / "cowrie.log.2020-01-01"
        recent_json = tmp_path / "cowrie.json.2026-07-29"
        for f in (live_json, live_log, old_json, old_log, recent_json):
            f.write_text("{}\n")

        old_epoch = time.time() - 45 * 86400
        recent_epoch = time.time() - 5 * 86400
        os.utime(old_json, (old_epoch, old_epoch))
        os.utime(old_log, (old_epoch, old_epoch))
        os.utime(recent_json, (recent_epoch, recent_epoch))
        # Live files would legitimately be much older than 30 days too (they
        # only get replaced at the next midnight rotation) - proves they're
        # excluded by name, not by luckily looking "recent".
        os.utime(live_json, (old_epoch, old_epoch))
        os.utime(live_log, (old_epoch, old_epoch))

        monkeypatch.setenv("COWRIE_LOG_FILE", str(live_json))
        cleanup = fresh_module("cleanup")

        cleanup.cleanup_old_cowrie_log_files()

        remaining = {p.name for p in tmp_path.iterdir()}
        assert remaining == {"cowrie.json", "cowrie.log", "cowrie.json.2026-07-29"}


# ---------------------------------------------------------------------------
# backup.py: mongodump-based automated backup + retention. subprocess.run is
# always mocked here - backup.py shells out to a real `mongodump` binary
# rather than going through pymongo, so it's the one script in this project
# that ISN'T covered by conftest.py's `_never_touch_real_mongo` MongoClient
# patch. Never let a test invoke the real binary against a real mongod.
# ---------------------------------------------------------------------------
class TestBackup:
    def _mock_mongodump_success(self, monkeypatch, backup):
        """Simulates mongodump succeeding: writes a small dummy file at the
        --archive= path (so the real os.path.getsize() call afterwards has
        something to measure) and returns rc=0, without ever touching a
        real mongod."""
        def fake_run(cmd, **kwargs):
            archive_path = next(a.split("=", 1)[1] for a in cmd if a.startswith("--archive="))
            with open(archive_path, "wb") as f:
                f.write(b"fake mongodump archive")
            return Mock(returncode=0, stderr="")
        monkeypatch.setattr(backup.subprocess, "run", Mock(side_effect=fake_run))

    def test_bk01_successful_backup_creates_archive_and_updates_metrics(
        self, fresh_module, monkeypatch, tmp_path
    ):
        backup = fresh_module("backup")
        monkeypatch.setattr(backup, "BACKUP_DIR", str(tmp_path))
        self._mock_mongodump_success(monkeypatch, backup)

        backup.run_backup()

        archives = list(tmp_path.glob("honeypot_*.archive.gz"))
        assert len(archives) == 1
        assert backup.metrics.BACKUP_LAST_ARCHIVE_BYTES._value.get() == len(b"fake mongodump archive")

    def test_bk02_failed_mongodump_does_not_leave_a_partial_archive(
        self, fresh_module, monkeypatch, tmp_path
    ):
        backup = fresh_module("backup")
        monkeypatch.setattr(backup, "BACKUP_DIR", str(tmp_path))

        def fake_run_failure(cmd, **kwargs):
            archive_path = next(a.split("=", 1)[1] for a in cmd if a.startswith("--archive="))
            with open(archive_path, "wb") as f:
                f.write(b"truncated")  # mongodump can leave a partial file before failing
            return Mock(returncode=1, stderr="Failed: connection refused")
        monkeypatch.setattr(backup.subprocess, "run", Mock(side_effect=fake_run_failure))

        backup.run_backup()

        assert list(tmp_path.glob("honeypot_*.archive.gz")) == []

    def test_bk03_missing_mongodump_binary_does_not_crash(self, fresh_module, monkeypatch, tmp_path):
        backup = fresh_module("backup")
        monkeypatch.setattr(backup, "BACKUP_DIR", str(tmp_path))
        monkeypatch.setattr(backup.subprocess, "run", Mock(side_effect=FileNotFoundError()))

        backup.run_backup()  # must not raise

        assert list(tmp_path.glob("honeypot_*.archive.gz")) == []

    def test_bk04_retention_deletes_only_backups_older_than_the_window(
        self, fresh_module, monkeypatch, tmp_path
    ):
        backup = fresh_module("backup")
        monkeypatch.setattr(backup, "BACKUP_DIR", str(tmp_path))
        monkeypatch.setattr(backup, "BACKUP_RETENTION_DAYS", 7)

        old = tmp_path / "honeypot_20200101_000000.archive.gz"
        recent = tmp_path / "honeypot_20260801_000000.archive.gz"
        old.write_bytes(b"old")
        recent.write_bytes(b"recent")
        old_epoch = time.time() - 45 * 86400
        os.utime(old, (old_epoch, old_epoch))

        backup.cleanup_old_backups()

        remaining = {p.name for p in tmp_path.iterdir()}
        assert remaining == {"honeypot_20260801_000000.archive.gz"}


# ---------------------------------------------------------------------------
# PL-14: parser.py's import_log_file() (batch import, not tailing)
# ---------------------------------------------------------------------------
class TestParserImportLogFile:
    def test_pl14_import_counts_and_skips_correctly(self, fresh_module, tmp_path):
        parser = fresh_module("parser")

        lines = [
            "",  # blank line - ignored, counted as neither inserted nor skipped
            json.dumps(make_login_failed_event(session="s1")),  # IMPORTANT -> inserted
            '{"eventid": "cowrie.login.failed", "broken"',  # malformed JSON -> ignored
            json.dumps(make_client_version_event(session="s1")),  # valid JSON, not IMPORTANT -> skipped
            json.dumps(make_login_success_event(session="s1")),  # IMPORTANT -> inserted
        ]
        log_file = tmp_path / "sample.json"
        log_file.write_text("\n".join(lines) + "\n")

        parser.import_log_file(str(log_file))

        assert parser.collection.count_documents({}) == 2
        events = {d["event"] for d in parser.collection.find({}, {"_id": 0, "event": 1})}
        assert events == {"cowrie.login.failed", "cowrie.login.success"}

    def test_pl14_import_log_file_never_drops_the_collection(self, fresh_module, tmp_path):
        """
        import_log_file() itself must never call collection.drop() - that
        only happens inside parser.py's `if __name__ == "__main__":` guard,
        which does not execute on import. Pinning this down specifically
        because accidentally moving drop() out of that guard would wipe the
        real honeypot database in production.
        """
        parser = fresh_module("parser")
        parser.collection.insert_one({"session": "pre-existing"})

        log_file = tmp_path / "sample.json"
        log_file.write_text(json.dumps(make_login_failed_event(session="new")) + "\n")
        parser.import_log_file(str(log_file))

        sessions = {d["session"] for d in parser.collection.find({}, {"_id": 0, "session": 1})}
        assert sessions == {"pre-existing", "new"}
