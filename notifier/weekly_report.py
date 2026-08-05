import html
import os
import time
from datetime import datetime, timedelta, timezone

import schedule
from pymongo import MongoClient
from prometheus_client import start_http_server

from bot import send_message
from notify_log_setup import get_logger
import notify_metrics

logger = get_logger(__name__)

METRICS_PORT = 9106


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


def _esc(value) -> str:
    """html.escape() attacker-controlled fields before they land in a
    parse_mode=HTML Telegram message - local copy, not shared, same
    convention as bot.py/daily_report.py/telegram_commands.py (see
    CLAUDE.md)."""
    return html.escape(str(value)) if value is not None else ""


def compile_weekly_report() -> dict:
    now = datetime.now(timezone.utc)
    week_start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    prev_week_start = (now - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%S")

    this_week_filter = {"timestamp": {"$gte": week_start}}
    prev_week_filter = {"timestamp": {"$gte": prev_week_start, "$lt": week_start}}

    top_countries = list(collection.aggregate([
        {"$match": {**this_week_filter, "country": {"$nin": [None, "Local"]}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]))
    top_techniques = list(collection.aggregate([
        {"$match": this_week_filter},
        {"$unwind": "$mitre_techniques"},
        {"$group": {"_id": "$mitre_techniques", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]))

    return {
        "total_this_week": collection.count_documents(this_week_filter),
        "total_prev_week": collection.count_documents(prev_week_filter),
        "unique_ips":      len(collection.distinct("src_ip", this_week_filter)),
        "login_success":   collection.count_documents({**this_week_filter, "event": "cowrie.login.success"}),
        "login_failed":    collection.count_documents({**this_week_filter, "event": "cowrie.login.failed"}),
        "top_countries":   top_countries,
        "top_techniques":  top_techniques,
    }


def send_weekly_report():
    logger.info("Compiling weekly report")
    notify_metrics.WEEKLY_REPORT_RUNS.inc()
    data = compile_weekly_report()

    if data["total_prev_week"] > 0:
        change_pct = round(
            (data["total_this_week"] - data["total_prev_week"]) / data["total_prev_week"] * 100
        )
        trend = f"(📈 +{change_pct}% so với tuần trước)" if change_pct >= 0 else f"(📉 {change_pct}% so với tuần trước)"
    else:
        trend = ""

    countries_str = "\n".join(
        f"  {i + 1}. {_esc(c['_id'])} — {c['count']} lượt" for i, c in enumerate(data["top_countries"])
    ) or "  Chưa có dữ liệu"
    techniques_str = "\n".join(
        f"  {i + 1}. <code>{_esc(t['_id'])}</code> — {t['count']} lần" for i, t in enumerate(data["top_techniques"])
    ) or "  Chưa có dữ liệu"

    now = datetime.now()
    msg = (
        f"📆 <b>BÁO CÁO HONEYPOT HÀNG TUẦN</b>\n"
        f"<i>{(now - timedelta(days=7)).strftime('%d/%m')} — {now.strftime('%d/%m/%Y')}</i>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Tổng sự kiện: <b>{data['total_this_week']}</b> {trend}\n"
        f"👤 IP unique: <b>{data['unique_ips']}</b>\n"
        f"✅ Đăng nhập OK: <b>{data['login_success']}</b>\n"
        f"❌ Đăng nhập sai: <b>{data['login_failed']}</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🌍 <b>Top 5 quốc gia:</b>\n{countries_str}\n\n"
        f"🎯 <b>Top 5 kỹ thuật MITRE ATT&CK:</b>\n{techniques_str}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"⏰ <i>Báo cáo tự động lúc {now.strftime('%H:%M:%S %d/%m/%Y')}</i>"
    )

    if send_message(msg):
        logger.info("Weekly report sent to Telegram")
        notify_metrics.WEEKLY_REPORT_LAST_SUCCESS_TIMESTAMP.set(time.time())
    else:
        logger.error("Failed to send weekly report to Telegram")
        notify_metrics.WEEKLY_REPORT_SEND_FAILURES.inc()


# Thứ Hai hàng tuần, 08:30 (lệch với daily_report.py's 08:00 để 2 job không
# gửi Telegram cùng lúc)
schedule.every().monday.at("08:30").do(send_weekly_report)

if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    logger.info("Weekly report scheduler starting, scheduled for Monday 08:30")
    send_weekly_report()  # Test ngay
    while True:
        schedule.run_pending()
        time.sleep(60)
