"""
Watches MongoDB for http.login.attempt documents inserted by
parser/http_honeypot.py (the fake HTTP admin login page - see CLAUDE.md)
and fires a Telegram alert for each, then marks it alerted=True.

Unlike realtime_alert.py, this doesn't tail a Cowrie-style log file and
doesn't insert a second, duplicate document - parser/http_honeypot.py
already writes ONE complete document (geo/MITRE tag included) straight to
MongoDB with alerted=False, so this watcher just polls for those and
claims/updates that same document in place instead.
"""

import os
import time

from prometheus_client import start_http_server
from pymongo import MongoClient

from bot import alert_http_login_attempt
from notify_log_setup import get_logger
import notify_metrics

logger = get_logger(__name__)

METRICS_PORT = 9107
POLL_INTERVAL_SECONDS = 5

# Same per-IP cooldown model as realtime_alert.py - a scanner retrying the
# same credential-stuffing payload every few seconds would otherwise fire a
# fresh Telegram push per attempt. Duplicated rather than shared, same
# reasoning as every other per-file constant in this project (see
# CLAUDE.md).
ALERT_COOLDOWN_SECONDS = 5 * 60
_LAST_ALERT_TIME: dict[str, float] = {}


def _should_alert(ip: str) -> bool:
    now = time.time()
    last = _LAST_ALERT_TIME.get(ip)
    if last is not None and now - last < ALERT_COOLDOWN_SECONDS:
        return False
    _LAST_ALERT_TIME[ip] = now
    return True


def _read_secret(env_name: str):
    """Reads a secret from <env_name>_FILE (a file path) if set - the
    Docker Compose `secrets:` convention (see docker-compose.yml) - else
    falls back to the plain env var, which is what the native venv
    workflow uses. Duplicated per-file rather than shared, same as the
    other `_read_secret()`s in this project (see CLAUDE.md)."""
    file_path = os.getenv(f"{env_name}_FILE")
    if file_path:
        with open(file_path) as f:
            return f.read().strip()
    return os.getenv(env_name)


def _mongo_auth_kwargs() -> dict:
    """Adds MongoDB username/password auth if MONGO_USERNAME is set - the
    native venv workflow (mongod with no --auth) never sets it, so this
    returns {} and pymongo connects exactly as before."""
    username = _read_secret("MONGO_USERNAME")
    if not username:
        return {}
    return {
        "username": username,
        "password": _read_secret("MONGO_PASSWORD"),
        "authSource": os.getenv("MONGO_AUTH_SOURCE", "admin"),
    }


client     = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), **_mongo_auth_kwargs())
db         = client[os.getenv("DB_NAME", "honeypot")]
collection = db["attacks"]


def process_pending_login_attempts():
    """Claims and alerts on every currently-pending http.login.attempt doc.
    Split out from the poll loop below for testability."""
    for doc in collection.find({"event": "http.login.attempt", "alerted": False}):
        # Atomic claim - find_one_and_update on _id + still-False alerted
        # guards against double-sending if this ever runs with more than
        # one worker (it doesn't today, but costs nothing to be safe).
        claimed = collection.find_one_and_update(
            {"_id": doc["_id"], "alerted": False},
            {"$set": {"alerted": True}},
        )
        if claimed is None:
            continue

        ip = claimed.get("src_ip", "")
        if _should_alert(ip):
            alert_http_login_attempt(
                ip,
                claimed.get("username"),
                claimed.get("password"),
                claimed.get("path"),
            )
            logger.info(
                "Sent HTTP honeypot login-attempt Telegram alert",
                extra={"ip": ip, "event": "http.login.attempt"},
            )
            notify_metrics.TELEGRAM_ALERTS_SENT.labels("http.login.attempt").inc()
        notify_metrics.HTTP_HONEYPOT_ALERT_PROCESSED.inc()


def poll_forever():
    logger.info("HTTP honeypot alert watcher starting (poll every %ds)", POLL_INTERVAL_SECONDS)
    while True:
        try:
            process_pending_login_attempts()
        except Exception:
            logger.error("Unexpected error in HTTP honeypot alert poll loop", exc_info=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    poll_forever()
