"""
Prometheus metric definitions for the API.

Kept in its own module (not main.py) so auth.py can import and increment
API_RATE_LIMIT_REJECTIONS without a circular import - main.py already
imports auth, so auth importing main back would be circular.

/metrics itself is exposed directly on `app` in main.py, not on
api_router: it must stay reachable without a login cookie (Prometheus has
no way to authenticate against this app's JWT/cookie flow) and is
deliberately not subject to the generic per-IP /api/* rate limit, which
exists to protect the attack-data endpoints, not this project's own
monitoring endpoint.
"""

from __future__ import annotations

from prometheus_client import REGISTRY, Counter, Gauge, Histogram

HTTP_REQUESTS = Counter(
    "honeypot_http_requests_total",
    "HTTP requests received by the API",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "honeypot_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
)

LOGIN_ATTEMPTS = Counter(
    "honeypot_login_attempts_total",
    "Dashboard/API login attempts via POST /auth/login",
    ["result"],  # "success" or "failed"
)

API_RATE_LIMIT_REJECTIONS = Counter(
    "honeypot_api_rate_limit_rejections_total",
    "Requests rejected by the generic per-IP /api/* rate limit (auth.check_api_rate_limit)",
)

# --- log_watcher.py (exposed on its own /metrics via start_http_server, see
# log_watcher.py's __main__ block - it's not an HTTP server otherwise) -----
# Metric names are prefixed "log_watcher_", not just "watcher_", specifically
# so they can't collide with notifier/notify_metrics.py's realtime_alert_*
# equivalents - tests/test_alerting.py's schema-consistency test imports
# both log_watcher.py and realtime_alert.py into the SAME process, and
# prometheus_client's default registry is a process-wide singleton that
# rejects two different Counter objects registered under the same name,
# even though in production these always run as separate processes.
LOG_WATCHER_EVENTS_PROCESSED = Counter(
    "honeypot_log_watcher_events_processed_total",
    "Cowrie events successfully inserted into MongoDB by log_watcher.py",
    ["event"],
)
LOG_WATCHER_INSERT_ERRORS = Counter(
    "honeypot_log_watcher_insert_errors_total",
    "MongoDB insert failures encountered by log_watcher.py",
)
LOG_WATCHER_LAST_EVENT_TIMESTAMP = Gauge(
    "honeypot_log_watcher_last_event_timestamp_seconds",
    "Unix timestamp log_watcher.py last processed a Cowrie event - a "
    "stalled or crashed watcher stops advancing this. Events during any "
    "downtime are recovered once it restarts (see OFFSET_FILE in "
    "log_watcher.py), but this is still how you'd notice it's down NOW "
    "rather than after the fact",
)
LOG_WATCHER_LOG_ROTATIONS = Counter(
    "honeypot_log_watcher_log_rotations_total",
    "Times log_watcher.py detected and recovered from a Cowrie log rotation",
)

# --- cleanup.py (also exposed on its own /metrics) -------------------------
CLEANUP_RUNS = Counter(
    "honeypot_cleanup_runs_total", "Number of times the 30-day retention cleanup job has run"
)
CLEANUP_DELETED_TOTAL = Counter(
    "honeypot_cleanup_deleted_total", "Total attack documents deleted by the cleanup job"
)
CLEANUP_LAST_RUN_TIMESTAMP = Gauge(
    "honeypot_cleanup_last_run_timestamp_seconds", "Unix timestamp of the last cleanup run"
)
CLEANUP_COWRIE_LOG_FILES_DELETED_TOTAL = Counter(
    "honeypot_cleanup_cowrie_log_files_deleted_total",
    "Rotated Cowrie cowrie.log.*/cowrie.json.* files deleted by the cleanup job "
    "(the live cowrie.log/cowrie.json files are never touched)",
)
CLEANUP_COWRIE_LOG_BYTES_DELETED_TOTAL = Counter(
    "honeypot_cleanup_cowrie_log_bytes_deleted_total",
    "Total bytes freed by deleting old rotated Cowrie log files",
)

# --- backup.py (also exposed on its own /metrics) ---------------------------
BACKUP_RUNS = Counter(
    "honeypot_backup_runs_total", "Number of times the mongodump backup job has run"
)
BACKUP_FAILURES = Counter(
    "honeypot_backup_failures_total", "Number of backup runs where mongodump exited non-zero"
)
BACKUP_LAST_SUCCESS_TIMESTAMP = Gauge(
    "honeypot_backup_last_success_timestamp_seconds",
    "Unix timestamp of the last backup that completed successfully - a stalled/broken backup "
    "job stops advancing this even if the process is still 'running'",
)
BACKUP_LAST_ARCHIVE_BYTES = Gauge(
    "honeypot_backup_last_archive_bytes", "Size in bytes of the most recent backup archive"
)
BACKUP_DELETED_TOTAL = Counter(
    "honeypot_backup_deleted_total", "Old backup archives deleted by the retention policy"
)

_current_mongo_stats_collector = None


def register_mongo_stats_collector(collector) -> None:
    """Replaces any previously-registered Mongo-stats collector, rather
    than just registering a new one, for the same reason this module (not
    main.py) holds the reference: prometheus_client's default REGISTRY is
    a genuine process-wide singleton, unaffected by tests' fresh_app/
    fresh_module fixtures popping "main" from sys.modules and re-importing
    it fresh per test. Without replacing the old registration, only the
    FIRST test's collector - a closure over that test's own, now-discarded
    mongomock collection - would ever be scraped for the rest of the
    session, silently making every later test's /metrics output stale.
    Real production only ever calls this once (uvicorn imports main.py a
    single time), so the "replace" branch never runs there."""
    global _current_mongo_stats_collector
    if _current_mongo_stats_collector is not None:
        REGISTRY.unregister(_current_mongo_stats_collector)
    REGISTRY.register(collector)
    _current_mongo_stats_collector = collector
