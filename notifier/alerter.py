import json
import time
import os
from bot import alert_login_failed, alert_login_success, alert_command

# Đường dẫn tới file log của Honeypot
LOG_FILE = "../honeypot/cowrie.json"

# Dictionary để lưu số lần đăng nhập sai của từng IP
failed_attempts = {}

def process_log_line(line):
    try:
        # Chuyển dòng text thành object JSON
        data = json.loads(line)
        eventid = data.get("eventid")
        src_ip = data.get("src_ip")

        # 1. Nếu là sự kiện ĐĂNG NHẬP THẤT BẠI
        if eventid == "cowrie.login.failed":
            username = data.get("username", "")
            password = data.get("password", "")
            
            # Cộng dồn số lần sai
            failed_attempts[src_ip] = failed_attempts.get(src_ip, 0) + 1
            
            # Nếu sai đúng 5 lần thì cảnh báo (không báo liên tục gây spam)
            if failed_attempts[src_ip] == 5:
                print(f"[!] Phát hiện Brute-force từ IP: {src_ip}")
                alert_login_failed(src_ip, username, password, failed_attempts[src_ip])
                
        # 2. Nếu là sự kiện ĐĂNG NHẬP THÀNH CÔNG (CỰC KỲ NGUY HIỂM)
        elif eventid == "cowrie.login.success":
            username = data.get("username", "")
            password = data.get("password", "")
            print(f"[!!!] BÁO ĐỘNG: IP {src_ip} đã login thành công!")
            alert_login_success(src_ip, username, password)
            
        # 3. Nếu hacker gõ LỆNH (COMMAND) vào hệ thống
        elif eventid == "cowrie.command.input":
            command = data.get("input", "")
            print(f"[*] IP {src_ip} vừa gõ lệnh: {command}")
            alert_command(src_ip, command)
            
    except json.JSONDecodeError:
        pass # Bỏ qua nếu dòng log bị lỗi định dạng

def monitor_log():
    # Kiểm tra xem file log có tồn tại không
    if not os.path.exists(LOG_FILE):
        print(f"❌ Không tìm thấy file {LOG_FILE}. Hãy chắc chắn Honeypot đang chạy!")
        return

    print(f"✅ Đang nằm vùng giám sát file log: {LOG_FILE}...")
    
    with open(LOG_FILE, 'r') as f:
        # Nhảy đến cuối file, chỉ đọc những log MỚI XUẤT HIỆN từ bây giờ
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5) # Chờ nửa giây rồi đọc tiếp cho đỡ tốn CPU
                continue
            process_log_line(line)

if __name__ == "__main__":
    monitor_log()
