from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import os
import schedule
import time
from prometheus_client import start_http_server
import metrics

METRICS_PORT = 9102

client     = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))
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
