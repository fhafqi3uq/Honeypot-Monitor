import html
import time
import requests
import os
from pymongo import MongoClient
from dotenv import load_dotenv
from notify_log_setup import get_logger

load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

logger = get_logger(__name__)

client = MongoClient("mongodb://localhost:27017")
db = client["honeypot"]
col = db["attacks"]

def _esc(value) -> str:
    """html.escape() attacker-controlled fields before they land in a
    parse_mode=HTML Telegram message - value may be None."""
    return html.escape(str(value)) if value is not None else ""

def send_message(text):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML"})

def get_stats():
    total = col.count_documents({})
    success = col.count_documents({"event": "cowrie.login.success"})
    failed = col.count_documents({"event": "cowrie.login.failed"})
    return (f"📊 <b>THỐNG KÊ HỆ THỐNG</b>\n━━━━━━━━━━━━━━━\n"
            f"🔹 Tổng số logs: <b>{total}</b>\n"
            f"✅ Xâm nhập thành công: <b>{success}</b>\n"
            f"❌ Brute-force thất bại: <b>{failed}</b>")

def get_top_ips():
    pipeline = [
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top = list(col.aggregate(pipeline))
    if not top: return "⚠️ Dữ liệu trống."
    res = "🔝 <b>TOP 5 ATTACKER IPs</b>\n━━━━━━━━━━━━━━━\n"
    for i, item in enumerate(top, 1):
        res += f"{i}. <code>{_esc(item['_id'])}</code>: <b>{item['count']} lần</b>\n"
    return res

def get_recent_brute():
    recent = list(col.find({"event": "cowrie.login.failed"}).sort("created_at", -1).limit(5))
    if not recent: return "✅ Chưa có đợt tấn công nào."
    res = "🔑 <b>5 LẦN THỬ GẦN NHẤT</b>\n━━━━━━━━━━━━━━━\n"
    for b in recent:
        res += f"• <code>{_esc(b.get('src_ip'))}</code>: {_esc(b.get('username'))}/{_esc(b.get('password'))}\n"
    return res

def process_update(update):
    """Dispatch a single Telegram getUpdates() message - split out from
    handle_commands()'s polling loop so it can be unit tested directly
    without running the infinite loop."""
    message = update.get("message", {})
    text = message.get("text", "")

    # Anyone who messages this bot (not just the configured CHAT_ID) could
    # otherwise pull attack stats and plaintext attacker-tried passwords via
    # /brute - reject everything from an unrecognized chat before
    # dispatching a command.
    sender_chat_id = message.get("chat", {}).get("id")
    if str(sender_chat_id) != str(CHAT_ID):
        if text:
            logger.warning("Rejected Telegram command from unauthorized chat")
        return

    if text == "/stats":
        send_message(get_stats())
    elif text == "/top":
        send_message(get_top_ips())
    elif text == "/brute":
        send_message(get_recent_brute())
    elif text == "/help":
        send_message("❓ <b>DANH SÁCH LỆNH:</b>\n/stats - Thống kê\n/top - Top IP\n/brute - Log thử pass\n/help - Hỗ trợ")


def handle_commands():
    last_update_id = 0
    logger.info("Telegram command bot starting")
    while True:
        try:
            url = f"https://api.telegram.org/bot{TOKEN}/getUpdates?offset={last_update_id + 1}&timeout=30"
            resp = requests.get(url, timeout=35).json()
            for update in resp.get("result", []):
                last_update_id = update["update_id"]
                process_update(update)
        except Exception:
            logger.error("Unexpected error in handle_commands loop", exc_info=True)
        time.sleep(1)

if __name__ == "__main__":
    handle_commands()
