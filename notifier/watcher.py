import time
import requests
from bot import alert_login_failed, alert_login_success, alert_command

API_URL = "http://localhost:8000"

def check_alerts():
    try:
        res    = requests.get(f"{API_URL}/api/alerts/pending", timeout=5)
        alerts = res.json().get("data", [])

        for a in alerts:
            event    = a.get("event", "")
            ip       = a.get("src_ip", "?")
            username = a.get("username", "?")
            password = a.get("password", "?")
            command  = a.get("command", "?")

            if event == "cowrie.login.failed":
                alert_login_failed(ip, username, password, 1)
                print(f"⚠️  Sent brute-force alert: {ip}")

            elif event == "cowrie.login.success":
                alert_login_success(ip, username, password)
                print(f"🚨 Sent login success alert: {ip}")

            elif event == "cowrie.command.input":
                alert_command(ip, command)
                print(f"💻 Sent command alert: {ip}")

    except Exception as e:
        print(f"❌ Lỗi kết nối API: {e}")

if __name__ == "__main__":
    print("🚀 Watcher đang chạy, kiểm tra mỗi 30 giây...")
    print("   Nhấn Ctrl+C để dừng\n")
    while True:
        check_alerts()
        time.sleep(30)
