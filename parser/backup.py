import glob
import os
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import quote_plus

import schedule
from prometheus_client import start_http_server

import metrics

METRICS_PORT = 9105

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "honeypot")
BACKUP_DIR = os.getenv("BACKUP_DIR", os.path.expanduser("~/Honeypot-Monitor/backups"))
BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "7"))


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


def _mongo_uri() -> str:
    """mongodump takes one connection URI rather than separate --username/
    --password flags, so credentials (if any) need to be embedded here -
    the native venv workflow never sets MONGO_USERNAME, so this returns
    MONGO_URL completely unchanged there, same no-op behavior as every
    other file's _mongo_auth_kwargs()."""
    username = _read_secret("MONGO_USERNAME")
    if not username:
        return MONGO_URL
    password = _read_secret("MONGO_PASSWORD")
    auth_source = os.getenv("MONGO_AUTH_SOURCE", "admin")
    scheme, rest = MONGO_URL.split("://", 1)
    return f"{scheme}://{quote_plus(username)}:{quote_plus(password)}@{rest}/?authSource={auth_source}"


def cleanup_old_backups():
    cutoff = time.time() - BACKUP_RETENTION_DAYS * 86400
    deleted = 0
    for path in glob.glob(os.path.join(BACKUP_DIR, "honeypot_*.archive.gz")):
        try:
            if os.stat(path).st_mtime < cutoff:
                os.remove(path)
                deleted += 1
        except OSError:
            continue
    if deleted:
        print(f"[{datetime.now()}] Đã xoá {deleted} bản backup cũ hơn {BACKUP_RETENTION_DAYS} ngày")
    metrics.BACKUP_DELETED_TOTAL.inc(deleted)


def run_backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive_path = os.path.join(BACKUP_DIR, f"honeypot_{timestamp}.archive.gz")

    cmd = [
        "mongodump",
        f"--uri={_mongo_uri()}",
        f"--db={DB_NAME}",
        f"--archive={archive_path}",
        "--gzip",
    ]

    metrics.BACKUP_RUNS.inc()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        print(
            f"[{datetime.now()}] Backup failed: 'mongodump' not found - "
            "cài đặt bằng: sudo apt-get install -y mongodb-database-tools"
        )
        metrics.BACKUP_FAILURES.inc()
        return
    except subprocess.TimeoutExpired:
        print(f"[{datetime.now()}] Backup failed: mongodump vượt quá 600s, đã huỷ")
        metrics.BACKUP_FAILURES.inc()
        return

    if result.returncode != 0:
        print(f"[{datetime.now()}] mongodump exited {result.returncode}: {result.stderr[-500:]}")
        metrics.BACKUP_FAILURES.inc()
        if os.path.exists(archive_path):
            os.remove(archive_path)  # partial/corrupt archive - don't keep it
        return

    size = os.path.getsize(archive_path)
    print(f"[{datetime.now()}] Backup hoàn tất: {archive_path} ({size} bytes)")
    metrics.BACKUP_LAST_SUCCESS_TIMESTAMP.set(time.time())
    metrics.BACKUP_LAST_ARCHIVE_BYTES.set(size)

    cleanup_old_backups()


# 02:00 mỗi ngày - lệch giờ với cleanup.py (00:00) để 2 job không tranh tài
# nguyên/IO cùng lúc trên VPS nhỏ.
schedule.every().day.at("02:00").do(run_backup)

if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    print(f"💾 Auto backup MongoDB đang chạy — dump lúc 02:00 mỗi ngày, giữ {BACKUP_RETENTION_DAYS} ngày gần nhất")
    run_backup()  # Chạy ngay lần đầu
    while True:
        schedule.run_pending()
        time.sleep(60)
