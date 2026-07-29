"""
Structured JSON logging shared by notifier/ scripts (realtime_alert.py,
daily_report.py, bot.py).

Deliberately NOT named the same as parser/log_setup.py: pytest's conftest.py
puts both parser/ and notifier/ on sys.path for the whole test session, and
two same-named modules in different directories would collide in Python's
module cache. See parser/log_setup.py for the twin implementation - kept
separate rather than shared, consistent with how this project already
duplicates parse_event/get_geo between parser/ and notifier/ (see CLAUDE.md).

Each call to get_logger(name) returns a logging.Logger that writes one JSON
object per line to <repo_root>/logs/notifier.log.

Never pass TELEGRAM_TOKEN, ABUSEIPDB_KEY, or JWT/session tokens as the
message or as extra context - this file has no secret-scrubbing, it relies
on callers not logging secrets in the first place.
"""

from __future__ import annotations

import json
import logging
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOG_DIR = os.path.join(_REPO_ROOT, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "notifier.log")

_CONTEXT_KEYS = ("ip", "src_ip", "session", "username", "event")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }
        for key in _CONTEXT_KEYS:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured - avoid duplicate handlers on re-import
    os.makedirs(_LOG_DIR, exist_ok=True)
    handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
