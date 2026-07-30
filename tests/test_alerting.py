"""
Layer 3 test plan: Alerting / Telegram (AL-01 .. AL-11 from the test plan
table).

Every test goes through `fresh_module` (mongomock-backed) and the global
requests.post/requests.get poison pill from conftest.py - no test in this
file ever sends a real Telegram message, calls the real AbuseIPDB/ipinfo.io
APIs, or touches the real "honeypot" MongoDB database, even though
notifier/.env holds real credentials on disk.
"""

from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import Mock

import pytest
import requests

from conftest import (
    make_client_version_event,
    make_command_event,
    make_connect_event,
    make_kex_event,
    make_login_failed_event,
    make_login_success_event,
)


# ---------------------------------------------------------------------------
# AL-06, AL-07, AL-08: notifier/bot.py resilience (or lack thereof)
# ---------------------------------------------------------------------------
class TestBotResilience:
    def test_al06_send_message_retries_on_connection_error_then_fails_gracefully(
        self, fresh_module, monkeypatch
    ):
        """bot.send_message() now retries MAX_RETRIES times (with backoff)
        on a connection-level failure, then returns False instead of
        raising - a Telegram outage no longer crashes the caller
        (realtime_alert.py's single-threaded watch_log() loop)."""
        bot = fresh_module("bot")
        monkeypatch.setattr(bot.time, "sleep", lambda s: None)
        mock_post = Mock(side_effect=requests.exceptions.ConnectionError("DNS resolution failed"))
        monkeypatch.setattr(requests, "post", mock_post)

        result = bot.send_message("test alert")

        assert result is False
        assert mock_post.call_count == bot.MAX_RETRIES

    def test_al06_send_message_sets_a_timeout(self, fresh_module, monkeypatch):
        """A timeout is now set on every Telegram request - a hung/dead
        connection to Telegram no longer blocks the caller forever, and
        since realtime_alert.py's watch_log() loop is synchronous and
        single-threaded, that would otherwise stall the entire honeypot
        alert pipeline, not just this one alert."""
        bot = fresh_module("bot")
        mock_post = Mock(return_value=Mock(status_code=200))
        monkeypatch.setattr(requests, "post", mock_post)

        bot.send_message("test alert")

        _, kwargs = mock_post.call_args
        assert kwargs.get("timeout") == bot.REQUEST_TIMEOUT

    def test_al07_429_rate_limit_is_not_retried_or_backed_off(self, fresh_module, monkeypatch):
        bot = fresh_module("bot")
        mock_post = Mock(return_value=Mock(status_code=429))
        monkeypatch.setattr(requests, "post", mock_post)

        result = bot.send_message("too many alerts at once")

        assert result is False
        assert mock_post.call_count == 1, "no retry/backoff should happen on 429"

    def test_al08_abuseipdb_timeout_fails_safe_to_zero(self, fresh_module, monkeypatch):
        bot = fresh_module("bot")
        monkeypatch.setattr(bot.time, "sleep", lambda s: None)
        monkeypatch.setattr(requests, "get", Mock(side_effect=requests.exceptions.Timeout()))

        assert bot.check_abuseipdb("203.0.113.7") == 0

    def test_al08_abuseipdb_bad_json_fails_safe_to_zero(self, fresh_module, monkeypatch):
        bot = fresh_module("bot")
        bad_response = Mock()
        bad_response.json.side_effect = ValueError("not JSON")
        monkeypatch.setattr(requests, "get", Mock(return_value=bad_response))

        assert bot.check_abuseipdb("203.0.113.7") == 0

    def test_al08_abuseipdb_private_ip_never_calls_the_api(self, fresh_module, monkeypatch):
        bot = fresh_module("bot")
        mock_get = Mock()
        monkeypatch.setattr(requests, "get", mock_get)

        assert bot.check_abuseipdb("192.168.1.1") == 0
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Telegram HTML injection: attacker-controlled fields must be escaped before
# landing in a parse_mode="HTML" message, or a crafted command/username can
# break the message layout or (depending on Telegram's own HTML sanitizing)
# inject unexpected markup.
# ---------------------------------------------------------------------------
class TestTelegramHTMLEscaping:
    def _mock_ip_info(self, monkeypatch):
        # 127.0.0.1 short-circuits check_abuseipdb() without an HTTP call;
        # only the ipinfo.io lookup needs mocking.
        monkeypatch.setattr(
            requests, "get", Mock(return_value=Mock(json=Mock(return_value={
                "city": "Hanoi", "country": "VN", "org": "AS0 Test ISP", "loc": "21.0,105.8",
            })))
        )

    def test_al09_script_payload_in_command_is_escaped_not_executed(self, fresh_module, monkeypatch):
        bot = fresh_module("bot")
        self._mock_ip_info(monkeypatch)
        mock_post = Mock(return_value=Mock(status_code=200))
        monkeypatch.setattr(requests, "post", mock_post)

        bot.alert_command("127.0.0.1", "<script>alert(1)</script>")

        sent_text = mock_post.call_args.kwargs["json"]["text"]
        assert "<script>" not in sent_text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in sent_text

    def test_al09_img_onerror_payload_in_username_is_escaped(self, fresh_module, monkeypatch):
        bot = fresh_module("bot")
        self._mock_ip_info(monkeypatch)
        mock_post = Mock(return_value=Mock(status_code=200))
        monkeypatch.setattr(requests, "post", mock_post)

        bot.alert_login_failed("127.0.0.1", '<img src=x onerror=alert(1)>', "pw", 1)

        sent_text = mock_post.call_args.kwargs["json"]["text"]
        assert "<img" not in sent_text
        assert "&lt;img src=x onerror=alert(1)&gt;" in sent_text


# ---------------------------------------------------------------------------
# AL-01, AL-02, AL-03, AL-04, AL-05: realtime_alert.py event routing
# ---------------------------------------------------------------------------
class TestRealtimeAlertRouting:
    def _mock_all_alerts(self, module, monkeypatch):
        mocks = {
            "alert_login_failed": Mock(),
            "alert_login_success": Mock(),
            "alert_command": Mock(),
        }
        for name, mock in mocks.items():
            monkeypatch.setattr(module, name, mock)
        return mocks

    def test_al01_login_failed_triggers_alert_login_failed(self, fresh_module, monkeypatch):
        realtime_alert = fresh_module("realtime_alert")
        mocks = self._mock_all_alerts(realtime_alert, monkeypatch)

        realtime_alert.process_event(
            make_login_failed_event(src_ip="203.0.113.7", username="root", password="123456")
        )

        mocks["alert_login_failed"].assert_called_once_with("203.0.113.7", "root", "123456", 1)
        mocks["alert_login_success"].assert_not_called()
        mocks["alert_command"].assert_not_called()

    def test_al02_login_success_triggers_alert_login_success(self, fresh_module, monkeypatch):
        realtime_alert = fresh_module("realtime_alert")
        mocks = self._mock_all_alerts(realtime_alert, monkeypatch)

        realtime_alert.process_event(
            make_login_success_event(src_ip="203.0.113.7", username="root", password="toor")
        )

        mocks["alert_login_success"].assert_called_once_with("203.0.113.7", "root", "toor")
        mocks["alert_login_failed"].assert_not_called()
        mocks["alert_command"].assert_not_called()

    def test_al03_command_input_triggers_alert_command(self, fresh_module, monkeypatch):
        realtime_alert = fresh_module("realtime_alert")
        mocks = self._mock_all_alerts(realtime_alert, monkeypatch)

        realtime_alert.process_event(
            make_command_event(src_ip="203.0.113.7", command="cat /etc/shadow")
        )

        mocks["alert_command"].assert_called_once_with("203.0.113.7", "cat /etc/shadow")
        mocks["alert_login_failed"].assert_not_called()
        mocks["alert_login_success"].assert_not_called()

    def test_al04_events_outside_important_events_trigger_no_alert(self, fresh_module, monkeypatch):
        realtime_alert = fresh_module("realtime_alert")
        mocks = self._mock_all_alerts(realtime_alert, monkeypatch)

        realtime_alert.process_event(make_client_version_event())
        realtime_alert.process_event(make_kex_event())

        for mock in mocks.values():
            mock.assert_not_called()
        assert realtime_alert.collection.count_documents({}) == 0

    def test_al05_duplicate_events_are_not_deduplicated(self, fresh_module, monkeypatch):
        """Pins down CURRENT behaviour: there is no cooldown/dedup - the
        exact same failed-login line processed twice fires two separate
        Telegram alerts and creates two documents."""
        realtime_alert = fresh_module("realtime_alert")
        mocks = self._mock_all_alerts(realtime_alert, monkeypatch)

        raw = make_login_failed_event()
        realtime_alert.process_event(raw)
        realtime_alert.process_event(raw)

        assert mocks["alert_login_failed"].call_count == 2
        assert realtime_alert.collection.count_documents({}) == 2


# ---------------------------------------------------------------------------
# AL-09: notifier/daily_report.py fallback to sample_log.json
# ---------------------------------------------------------------------------
class TestDailyReportFallback:
    def test_al09_falls_back_to_sample_log_when_real_log_missing(
        self, fresh_module, monkeypatch, tmp_path
    ):
        daily_report = fresh_module("daily_report")

        today = datetime.now().strftime("%Y-%m-%d")
        sample_log = tmp_path / "sample.json"
        sample_log.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "eventid": "cowrie.session.connect",
                            "timestamp": f"{today}T01:00:00Z",
                            "src_ip": "203.0.113.7",
                        }
                    ),
                    json.dumps(
                        {
                            "eventid": "cowrie.login.failed",
                            "timestamp": f"{today}T01:00:01Z",
                            "src_ip": "203.0.113.7",
                            "username": "root",
                            "password": "123456",
                        }
                    ),
                ]
            )
            + "\n"
        )

        monkeypatch.setattr(daily_report, "LOG_FILE", str(tmp_path / "does-not-exist.json"))
        monkeypatch.setattr(daily_report, "SAMPLE_LOG", str(sample_log))

        stats = daily_report.process_logs()

        assert stats is not None
        assert stats["total_sessions"] == 1
        assert stats["login_failed"] == 1
        assert stats["unique_ips"] == {"203.0.113.7"}

    def test_al09_returns_none_and_sends_no_message_when_no_log_exists_at_all(
        self, fresh_module, monkeypatch
    ):
        daily_report = fresh_module("daily_report")
        monkeypatch.setattr(daily_report, "LOG_FILE", "/nonexistent/real.json")
        monkeypatch.setattr(daily_report, "SAMPLE_LOG", "/nonexistent/sample.json")
        mock_send = Mock()
        monkeypatch.setattr(daily_report, "send_message", mock_send)

        assert daily_report.process_logs() is None
        daily_report.send_daily_report()

        mock_send.assert_not_called()

    def test_al09_ignores_events_not_from_today(self, fresh_module, monkeypatch, tmp_path):
        daily_report = fresh_module("daily_report")
        sample_log = tmp_path / "sample.json"
        sample_log.write_text(
            json.dumps(
                {
                    "eventid": "cowrie.login.failed",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "src_ip": "203.0.113.7",
                    "username": "root",
                    "password": "x",
                }
            )
            + "\n"
        )

        monkeypatch.setattr(daily_report, "LOG_FILE", "/nonexistent/real.json")
        monkeypatch.setattr(daily_report, "SAMPLE_LOG", str(sample_log))

        stats = daily_report.process_logs()

        assert stats["login_failed"] == 0

    def test_al09_html_injection_in_username_password_command_is_escaped(
        self, fresh_module, monkeypatch, tmp_path
    ):
        """Regression test: send_daily_report() interpolates the top
        username/password and last command straight into a
        parse_mode=HTML Telegram message - same injection class fixed in
        bot.py/telegram_commands.py, but daily_report.py wasn't in scope
        for that fix and needed its own _esc() pass."""
        daily_report = fresh_module("daily_report")
        today = datetime.now().strftime("%Y-%m-%d")
        sample_log = tmp_path / "sample.json"
        sample_log.write_text(
            "\n".join(
                [
                    json.dumps({
                        "eventid": "cowrie.login.failed",
                        "timestamp": f"{today}T01:00:00Z",
                        "src_ip": "203.0.113.7",
                        "username": "<img src=x onerror=alert(1)>",
                        "password": "<script>alert(1)</script>",
                    }),
                    json.dumps({
                        "eventid": "cowrie.command.input",
                        "timestamp": f"{today}T01:00:01Z",
                        "src_ip": "203.0.113.7",
                        "input": "<b>rm -rf /</b>",
                    }),
                ]
            )
            + "\n"
        )
        monkeypatch.setattr(daily_report, "LOG_FILE", "/nonexistent/real.json")
        monkeypatch.setattr(daily_report, "SAMPLE_LOG", str(sample_log))
        mock_send = Mock()
        monkeypatch.setattr(daily_report, "send_message", mock_send)

        daily_report.send_daily_report()

        sent_text = mock_send.call_args.args[0]
        assert "<img" not in sent_text
        assert "<script>" not in sent_text
        assert "<b>rm -rf /</b>" not in sent_text
        assert "&lt;img src=x onerror=alert(1)&gt;" in sent_text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in sent_text
        assert "&lt;b&gt;rm -rf /&lt;/b&gt;" in sent_text


# ---------------------------------------------------------------------------
# AL-10: notifier/telegram_commands.py query helpers
# ---------------------------------------------------------------------------
class TestTelegramCommands:
    def test_al10_get_stats_on_empty_db(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        result = telegram_commands.get_stats()
        assert "Tổng số logs: <b>0</b>" in result

    def test_al10_get_stats_with_data(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        telegram_commands.col.insert_many(
            [
                {"event": "cowrie.login.success"},
                {"event": "cowrie.login.failed"},
                {"event": "cowrie.login.failed"},
            ]
        )

        result = telegram_commands.get_stats()

        assert "Tổng số logs: <b>3</b>" in result
        assert "Xâm nhập thành công: <b>1</b>" in result
        assert "Brute-force thất bại: <b>2</b>" in result

    def test_al10_get_top_ips_on_empty_db(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        assert telegram_commands.get_top_ips() == "⚠️ Dữ liệu trống."

    def test_al10_get_top_ips_with_data(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        telegram_commands.col.insert_many(
            [{"src_ip": "203.0.113.7"}, {"src_ip": "203.0.113.7"}, {"src_ip": "198.51.100.1"}]
        )

        result = telegram_commands.get_top_ips()

        assert "203.0.113.7" in result
        assert "2 lần" in result

    def test_al10_get_recent_brute_on_empty_db(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        assert telegram_commands.get_recent_brute() == "✅ Chưa có đợt tấn công nào."

    def test_al10_get_recent_brute_with_data(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        telegram_commands.col.insert_one(
            {
                "event": "cowrie.login.failed",
                "src_ip": "203.0.113.7",
                "username": "root",
                "password": "toor",
                "created_at": datetime.utcnow(),
            }
        )

        result = telegram_commands.get_recent_brute()

        assert "203.0.113.7" in result
        assert "root/toor" in result

    def test_al12_get_recent_brute_escapes_html_injection(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        telegram_commands.col.insert_one(
            {
                "event": "cowrie.login.failed",
                "src_ip": "203.0.113.7",
                "username": "<img src=x onerror=alert(1)>",
                "password": "<script>alert(1)</script>",
                "created_at": datetime.utcnow(),
            }
        )

        result = telegram_commands.get_recent_brute()

        assert "<img" not in result
        assert "<script>" not in result
        assert "&lt;img src=x onerror=alert(1)&gt;" in result
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in result

    def test_al12_get_top_ips_escapes_html_injection(self, fresh_module):
        telegram_commands = fresh_module("telegram_commands")
        telegram_commands.col.insert_one({"src_ip": "<script>alert(1)</script>"})

        result = telegram_commands.get_top_ips()

        assert "<script>" not in result
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in result

    def test_al12_process_update_rejects_command_from_unauthorized_chat(self, fresh_module, monkeypatch):
        """Regression test for a fixed gap: process_update() used to
        dispatch ANY incoming Telegram message regardless of which chat it
        came from - so anyone who could message this bot could pull
        /stats, /top, or /brute (including plaintext attacker-tried
        passwords). It must now only respond to the configured CHAT_ID."""
        telegram_commands = fresh_module("telegram_commands")
        monkeypatch.setattr(telegram_commands, "CHAT_ID", "111111")
        mock_send = Mock()
        monkeypatch.setattr(telegram_commands, "send_message", mock_send)

        telegram_commands.process_update(
            {"update_id": 1, "message": {"chat": {"id": 999999}, "text": "/brute"}}
        )

        mock_send.assert_not_called()

    def test_al12_process_update_accepts_command_from_authorized_chat(self, fresh_module, monkeypatch):
        telegram_commands = fresh_module("telegram_commands")
        monkeypatch.setattr(telegram_commands, "CHAT_ID", "111111")
        mock_send = Mock()
        monkeypatch.setattr(telegram_commands, "send_message", mock_send)

        telegram_commands.process_update(
            {"update_id": 1, "message": {"chat": {"id": 111111}, "text": "/stats"}}
        )

        mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# AL-11: schema drift between log_watcher.py and realtime_alert.py
# ---------------------------------------------------------------------------
class TestSchemaConsistency:
    def test_al11_log_watcher_and_realtime_alert_produce_matching_schema(
        self, fresh_module, monkeypatch
    ):
        """
        parser/log_watcher.py and notifier/realtime_alert.py hand-duplicate
        the same parse/enrichment logic (see CLAUDE.md's explicit warning
        about this). Feed the identical event sequence through both and
        assert the resulting documents match field-for-field except
        `alerted` (False vs True) and `created_at` (wall-clock timestamps).
        If someone updates one file's document shape and forgets the
        other, this test catches it.
        """
        log_watcher = fresh_module("log_watcher")
        realtime_alert = fresh_module("realtime_alert")
        for name in ("alert_login_failed", "alert_login_success", "alert_command"):
            monkeypatch.setattr(realtime_alert, name, Mock())

        events = [
            make_connect_event(src_port=51234, dst_port=2222),
            make_client_version_event(version="SSH-2.0-OpenSSH_for_Windows_8.1"),
            make_kex_event(hassh="ec7378c1a92f5a8dde7e8b7a1ddf33d1"),
            make_login_failed_event(),
        ]

        for raw in events:
            log_watcher.update_session_cache(raw)
            doc = log_watcher.parse_event(raw)
            if doc:
                log_watcher.collection.insert_one(doc)

        for raw in events:
            realtime_alert.process_event(raw)

        lw_doc = log_watcher.collection.find_one({"event": "cowrie.login.failed"}, {"_id": 0})
        ra_doc = realtime_alert.collection.find_one({"event": "cowrie.login.failed"}, {"_id": 0})

        assert set(lw_doc.keys()) == set(ra_doc.keys()), "documents have drifted apart in shape"

        ignored_fields = {"alerted", "created_at"}
        for key in lw_doc.keys() - ignored_fields:
            assert lw_doc[key] == ra_doc[key], f"field '{key}' differs: {lw_doc[key]!r} vs {ra_doc[key]!r}"

        assert lw_doc["alerted"] is False
        assert ra_doc["alerted"] is True
