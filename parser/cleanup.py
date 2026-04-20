from pymongo import MongoClient
from datetime import datetime, timedelta
import schedule
import time

client     = MongoClient("mongodb://localhost:27017")
db         = client["honeypot"]
collection = db["attacks"]

def cleanup_old_logs():
    cutoff = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
    result = collection.delete_many({"timestamp": {"$lt": cutoff}})
    print(f"[{datetime.now()}] Đã xoá {result.deleted_count} log cũ hơn 30 ngày")

# Chạy lúc 00:00 mỗi ngày
schedule.every().day.at("00:00").do(cleanup_old_logs)

if __name__ == "__main__":
    print("🗑️ Auto cleanup đang chạy — xoá log cũ hơn 30 ngày lúc 00:00 mỗi ngày")
    cleanup_old_logs()  # Chạy ngay lần đầu
    while True:
        schedule.run_pending()
        time.sleep(60)
