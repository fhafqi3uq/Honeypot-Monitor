"""
Prometheus metric definitions for notifier/'s long-running scripts
(realtime_alert.py, daily_report.py, telegram_commands.py) - each exposes
these on its own /metrics via prometheus_client.start_http_server(), since
none of them are otherwise HTTP servers.

Deliberately NOT named metrics.py: parser/metrics.py already exists, and
both parser/ and notifier/ sit on sys.path simultaneously in the pytest
suite - two identically-named modules would collide in Python's module
cache (same reasoning as notify_log_setup.py vs log_setup.py, see
CLAUDE.md).

Metric names are prefixed "realtime_alert_", not just "watcher_" - kept
distinct from parser/metrics.py's log_watcher_* equivalents on purpose:
tests/test_alerting.py's schema-consistency test imports both
notifier/realtime_alert.py and parser/log_watcher.py into the SAME
process, and prometheus_client's default registry is a process-wide
singleton that rejects two different Counter objects registered under the
same name - even though in production these always run as separate
processes (this collision was hit and fixed while building this out).
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge

# --- realtime_alert.py ------------------------------------------------------
REALTIME_ALERT_EVENTS_PROCESSED = Counter(
    "honeypot_realtime_alert_events_processed_total",
    "Cowrie events successfully inserted into MongoDB by realtime_alert.py",
    ["event"],
)
REALTIME_ALERT_INSERT_ERRORS = Counter(
    "honeypot_realtime_alert_insert_errors_total",
    "MongoDB insert failures encountered by realtime_alert.py",
)
REALTIME_ALERT_LAST_EVENT_TIMESTAMP = Gauge(
    "honeypot_realtime_alert_last_event_timestamp_seconds",
    "Unix timestamp realtime_alert.py last processed a Cowrie event - a "
    "stalled or crashed watcher stops advancing this",
)
REALTIME_ALERT_LOG_ROTATIONS = Counter(
    "honeypot_realtime_alert_log_rotations_total",
    "Times realtime_alert.py detected and recovered from a Cowrie log rotation",
)
TELEGRAM_ALERTS_SENT = Counter(
    "honeypot_telegram_alerts_sent_total",
    "Realtime Telegram alerts dispatched, by Cowrie event type",
    ["event"],
)

# --- daily_report.py --------------------------------------------------------
DAILY_REPORT_RUNS = Counter(
    "honeypot_daily_report_runs_total", "Number of times the daily report job has run"
)
DAILY_REPORT_LAST_SUCCESS_TIMESTAMP = Gauge(
    "honeypot_daily_report_last_success_timestamp_seconds",
    "Unix timestamp of the last successfully-sent daily report",
)
DAILY_REPORT_SEND_FAILURES = Counter(
    "honeypot_daily_report_send_failures_total", "Daily report runs where the Telegram send failed"
)

# --- weekly_report.py --------------------------------------------------------
WEEKLY_REPORT_RUNS = Counter(
    "honeypot_weekly_report_runs_total", "Number of times the weekly report job has run"
)
WEEKLY_REPORT_LAST_SUCCESS_TIMESTAMP = Gauge(
    "honeypot_weekly_report_last_success_timestamp_seconds",
    "Unix timestamp of the last successfully-sent weekly report",
)
WEEKLY_REPORT_SEND_FAILURES = Counter(
    "honeypot_weekly_report_send_failures_total", "Weekly report runs where the Telegram send failed"
)

# --- auto_block.py ------------------------------------------------------------
AUTO_BLOCK_TOTAL = Counter(
    "honeypot_auto_block_total", "IPs automatically firewalled off for exceeding the abuse threshold"
)
AUTO_BLOCK_FAILURES = Counter(
    "honeypot_auto_block_failures_total", "Attempts to auto-block an IP where the ufw command itself failed"
)

# --- http_honeypot_alert.py --------------------------------------------------
HTTP_HONEYPOT_ALERT_PROCESSED = Counter(
    "honeypot_http_honeypot_alert_processed_total",
    "http.login.attempt documents claimed and processed by http_honeypot_alert.py",
)

# --- telegram_commands.py ---------------------------------------------------
TELEGRAM_COMMANDS_PROCESSED = Counter(
    "honeypot_telegram_commands_processed_total",
    "Telegram bot commands processed, by command",
    ["command"],
)
TELEGRAM_COMMANDS_REJECTED = Counter(
    "honeypot_telegram_commands_rejected_total",
    "Telegram messages rejected for coming from an unauthorized chat_id",
)
