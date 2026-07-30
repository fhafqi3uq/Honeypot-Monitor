from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import glob
import os
import schedule
import time
from prometheus_client import start_http_server
import metrics

METRICS_PORT = 9102

# Same default path convention as log_watcher.py/realtime_alert.py/
# daily_report.py's own COWRIE_LOG_FILE env var (see CLAUDE.md).
COWRIE_LOG_FILE = os.getenv(
    "COWRIE_LOG_FILE",
    os.path.expanduser("~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"),
)
COWRIE_LOG_RETENTION_DAYS = int(os.getenv("COWRIE_LOG_RETENTION_DAYS", "30"))


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

def cleanup_old_logs():
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
    result = collection.delete_many({"timestamp": {"$lt": cutoff}})
    print(f"[{datetime.now()}] Đã xoá {result.deleted_count} log cũ hơn 30 ngày")
    metrics.CLEANUP_RUNS.inc()
    metrics.CLEANUP_DELETED_TOTAL.inc(result.deleted_count)
    metrics.CLEANUP_LAST_RUN_TIMESTAMP.set(time.time())


def cleanup_old_cowrie_log_files():
    """Deletes Cowrie's own rotated log files (cowrie.log.<date>,
    cowrie.json.<date>) older than COWRIE_LOG_RETENTION_DAYS. Cowrie's
    `logtype = rotating` setting (see etc/cowrie.cfg) makes it rotate both
    its text and JSON logs to a dated suffix every midnight forever, but
    Cowrie itself has no built-in retention - only the Mongo copy was ever
    pruned (cleanup_old_logs() above). Only matches the dated *.log.YYYY-MM-DD
    / *.json.YYYY-MM-DD glob, never the live cowrie.log/cowrie.json (no
    date suffix), which are always excluded by construction.
    """
    log_dir = os.path.dirname(COWRIE_LOG_FILE)
    cutoff_epoch = time.time() - COWRIE_LOG_RETENTION_DAYS * 86400
    deleted_files = 0
    deleted_bytes = 0
    for pattern in ("cowrie.log.*", "cowrie.json.*"):
        for path in glob.glob(os.path.join(log_dir, pattern)):
            try:
                stat = os.stat(path)
            except OSError:
                continue
            if stat.st_mtime < cutoff_epoch:
                deleted_bytes += stat.st_size
                os.remove(path)
                deleted_files += 1
    print(
        f"[{datetime.now()}] Đã xoá {deleted_files} file log Cowrie cũ hơn "
        f"{COWRIE_LOG_RETENTION_DAYS} ngày ({deleted_bytes} bytes)"
    )
    metrics.CLEANUP_COWRIE_LOG_FILES_DELETED_TOTAL.inc(deleted_files)
    metrics.CLEANUP_COWRIE_LOG_BYTES_DELETED_TOTAL.inc(deleted_bytes)


def cleanup_all():
    cleanup_old_logs()
    cleanup_old_cowrie_log_files()


# Chạy lúc 00:00 mỗi ngày
schedule.every().day.at("00:00").do(cleanup_all)

if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    print("🗑️ Auto cleanup đang chạy — xoá log cũ hơn 30 ngày lúc 00:00 mỗi ngày")
    cleanup_all()  # Chạy ngay lần đầu
    while True:
        schedule.run_pending()
        time.sleep(60)
