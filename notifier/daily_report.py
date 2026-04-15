import json
import os
import schedule
import time
from datetime import datetime, timedelta
from collections import Counter
from bot import send_message  # Gọi hàm từ file bot.py có sẵn của bạn

# Đường dẫn đến file log mẫu
LOG_FILE = os.path.join(os.path.dirname(__file__), '../honeypot/sample_log.json')

def process_logs():
    stats = {
        "total_sessions": 0,
        "login_success": 0,
        "login_failed": 0,
        "usernames": [],
        "passwords": [],
        "commands": [],
        "unique_ips": set()
    }

    if not os.path.exists(LOG_FILE):
        print(f"❌ Không tìm thấy file: {LOG_FILE}")
        return None

    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                # Cowrie logs thường có timestamp dạng: 2026-04-12T11:39:40.335530Z
                # Ở đây mình tạm thời lấy hết dữ liệu trong file để demo, 
                # Nếu muốn lọc 24h, bạn có thể so sánh event['timestamp']
                
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
    return stats

def send_daily_report():
    print(f"[{datetime.now()}] Đang tổng hợp báo cáo...")
    data = process_logs()
    
    if not data: return

    # Thống kê top 3
    top_users = Counter(data["usernames"]).most_common(3)
    top_pass = Counter(data["passwords"]).most_common(3)
    
    user_str = "\n".join([f"• {u[0]} ({u[1]} lần)" for u in top_users]) or "N/A"
    pass_str = "\n".join([f"• {p[0]} ({p[1]} lần)" for p in top_pass]) or "N/A"
    last_cmd = data["commands"][-1] if data["commands"] else "N/A"

    # Format tin nhắn HTML cho Telegram (phù hợp với bot.py của bạn)
    msg = (
        f"📊 <b>BÁO CÁO HONEΥPOT HÀNG NGÀY</b>\n"
        f"📅 <i>Ngày: {datetime.now().strftime('%d/%m/%Y')}</i>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <b>Tổng Sessions:</b> <code>{data['total_sessions']}</code>\n"
        f"👤 <b>IP duy nhất:</b> <code>{len(data['unique_ips'])}</code>\n\n"
        f"✅ <b>Đăng nhập OK:</b> <pre>{data['login_success']}</pre>\n"
        f"❌ <b>Đăng nhập SAI:</b> <code>{data['login_failed']}</code>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔝 <b>Top Username:</b>\n{user_str}\n\n"
        f"🔑 <b>Top Password:</b>\n{pass_str}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💻 <b>Lệnh cuối cùng:</b> <code>{last_cmd}</code>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"⏰ <i>Gửi tự động từ VMware Monitor</i>"
    )

    if send_message(msg):
        print("✅ Đã bắn báo cáo lên Telegram!")
    else:
        print("❌ Gửi tin nhắn thất bại.")

# Lập lịch chạy lúc 8:00 mỗi ngày
schedule.every().day.at("14:35").do(send_daily_report)

if __name__ == "__main__":
    print("🚀 Báo cáo tự động đang chạy. Đợi đến 08:00 AM...")
    
    # Nếu muốn chạy thử ngay bây giờ để xem kết quả, hãy để nó thẳng hàng như thế này:
   # send_daily_report() 
    
    while True:
        schedule.run_pending()
        time.sleep(60)
