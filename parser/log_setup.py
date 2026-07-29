"""
Structured JSON logging shared by parser/ scripts (log_watcher.py, main.py).

Each call to get_logger(name) returns a logging.Logger that writes one JSON
object per line to <repo_root>/logs/parser.log: timestamp, level, module,
message, plus whatever extra context fields (ip, session, username, event...)
the caller passes via `logger.info(msg, extra={"ip": ip})`.

Never pass JWT_SECRET_KEY, access/refresh token strings, or password hashes
as the message or as extra context - this file has no secret-scrubbing, it
relies on callers not logging secrets in the first place.
"""

from __future__ import annotations

import json
import logging
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOG_DIR = os.path.join(_REPO_ROOT, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "parser.log")

# Extra fields a caller may attach via `extra={...}` that get promoted to
# top-level keys in the JSON line instead of being dropped.
_CONTEXT_KEYS = ("ip", "src_ip", "session", "username", "event", "endpoint")


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
