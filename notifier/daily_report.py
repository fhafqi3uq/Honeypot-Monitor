import json
import os
import schedule
import time
from datetime import datetime
from collections import Counter
from bot import send_message

LOG_FILE = os.path.expanduser(
    "~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"
)
SAMPLE_LOG = os.path.join(os.path.dirname(__file__), '../honeypot/sample_log.json')

def process_logs():
    stats = {
        "total_sessions": 0,
        "login_success":  0,
        "login_failed":   0,
        "usernames":      [],
        "passwords":      [],
        "commands":       [],
        "unique_ips":     set()
    }

    # Ưu tiên log thật, fallback về sample log
    log_path = os.path.expanduser(LOG_FILE)
    if not os.path.exists(log_path):
        log_path = os.path.expanduser(SAMPLE_LOG)

    if not os.path.exists(log_path):
        print(f"❌ Không tìm thấy file log!")
        return None

    # Chỉ lấy log của ngày hôm nay
    today = datetime.now().strftime("%Y-%m-%d")
    count_today = 0

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                event     = json.loads(line.strip())
                timestamp = event.get("timestamp", "")

                # Bỏ qua log không phải hôm nay
                if not timestamp.startswith(today):
                    continue

                count_today += 1
                event_id = event.get("eventid")
                stats["unique_ips"].add(event.get("src_ip"))

                if event_id == "cowrie.session.connect":
                    stats["total_sessions"] += 1
                elif event_id == "cowrie.login.success":
                    stats["login_success"] += 1
                    stats["usernames"].append(event.get("username"))
                elif event_id == "cowrie.login.failed":
                    stats["login_failed"] += 1
                    stats["usernames"].append(event.get("username"))
                    stats["passwords"].append(event.get("password"))
                elif event_id == "cowrie.command.input":
                    stats["commands"].append(event.get("input"))
            except Exception:
                continue

    print(f"📋 Tìm thấy {count_today} sự kiện hôm nay ({today})")
    return stats

def send_daily_report():
    print(f"[{datetime.now()}] Đang tổng hợp báo cáo ngày {datetime.now().strftime('%d/%m/%Y')}...")
    data = process_logs()

    if not data:
        return

    top_users = Counter(data["usernames"]).most_common(3)
    top_pass  = Counter(data["passwords"]).most_common(3)

    user_str = "\n".join([f"  {i+1}. {u[0]} — {u[1]} lần" for i, u in enumerate(top_users)]) or "  Chưa có dữ liệu"
    pass_str = "\n".join([f"  {i+1}. {p[0]} — {p[1]} lần" for i, p in enumerate(top_pass)]) or "  Chưa có dữ liệu"
    last_cmd = data["commands"][-1] if data["commands"] else "Không có"

    # Đánh giá mức độ nguy hiểm
    if data["login_success"] > 0:
        danger = "🔴 NGUY HIỂM — Có kẻ đăng nhập thành công!"
    elif data["login_failed"] > 50:
        danger = "🟠 CẢNH BÁO — Brute-force mạnh!"
    elif data["login_failed"] > 10:
        danger = "🟡 CHÚ Ý — Có hoạt động tấn công"
    else:
        danger = "🟢 BÌNH THƯỜNG — Ít tấn công hôm nay"

    msg = (
        f"📊 <b>BÁO CÁO HONEYPOT HÀNG NGÀY</b>\n"
        f"📅 <i>{datetime.now().strftime('%d/%m/%Y')}</i>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"{danger}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Tổng sessions: <b>{data['total_sessions']}</b>\n"
        f"👤 IP unique: <b>{len(data['unique_ips'])}</b>\n"
        f"✅ Đăng nhập OK: <b>{data['login_success']}</b>\n"
        f"❌ Đăng nhập SAI: <b>{data['login_failed']}</b>\n"
        f"⌨️ Lệnh nguy hiểm: <b>{len(data['commands'])}</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔝 <b>Top 3 Username bị thử:</b>\n{user_str}\n\n"
        f"🔑 <b>Top 3 Password bị thử:</b>\n{pass_str}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💻 Lệnh cuối: <code>{last_cmd}</code>\n"
        f"⏰ <i>Báo cáo tự động lúc {datetime.now().strftime('%H:%M:%S')}</i>"
    )

    if send_message(msg):
        print("✅ Đã gửi báo cáo lên Telegram!")
    else:
        print("❌ Gửi thất bại.")

# Lập lịch 8h sáng mỗi ngày
schedule.every().day.at("08:00").do(send_daily_report)

if __name__ == "__main__":
    print("🚀 Scheduler đang chạy...")
    print(f"📋 Báo cáo tự động lúc 08:00 mỗi ngày")
    print(f"📅 Hôm nay: {datetime.now().strftime('%d/%m/%Y')}")

    # Test ngay
    send_daily_report()

    while True:
        schedule.run_pending()
        time.sleep(60)
