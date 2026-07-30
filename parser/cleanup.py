from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import os
import schedule
import time
from prometheus_client import start_http_server
import metrics

METRICS_PORT = 9102


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

# Chạy lúc 00:00 mỗi ngày
schedule.every().day.at("00:00").do(cleanup_old_logs)

if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    print("🗑️ Auto cleanup đang chạy — xoá log cũ hơn 30 ngày lúc 00:00 mỗi ngày")
    cleanup_old_logs()  # Chạy ngay lần đầu
    while True:
        schedule.run_pending()
        time.sleep(60)
