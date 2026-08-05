#!/bin/bash

NOTIFIER_DIR=~/Honeypot-Monitor/notifier
STATUS=0
RECOVERED_SERVICES=""
FAILED_SERVICES=""

send_telegram() {
    cd $NOTIFIER_DIR
    source venv/bin/activate
    python3 -c "
from bot import send_message
send_message('''$1''')
"
}

check_and_restart() {
    local name=$1
    local check_cmd=$2
    local restart_cmd=$3
    if eval "$check_cmd" > /dev/null 2>&1; then
        echo "✅ $name — đang chạy"
    else
        echo "❌ $name — DỪNG! Đang khởi động lại..."
        send_telegram "❌ <b>DỊCH VỤ BỊ DỪNG</b>
━━━━━━━━━━━━━━━
⛔ $name đã ngừng hoạt động!
🔄 Đang khởi động lại...
⏰ $(date '+%d/%m/%Y %H:%M:%S')"
        eval "$restart_cmd"
        sleep 3  # Chờ khởi động
        
        # Kiểm tra lại sau restart
        if eval "$check_cmd" > /dev/null 2>&1; then
            echo "✅ $name — đã khôi phục"
            RECOVERED_SERVICES="$RECOVERED_SERVICES\n✅ $name"
        else
            echo "❌ $name — vẫn không lên được!"
            send_telegram "🚨 <b>$name KHÔNG THỂ KHỞI ĐỘNG LẠI!</b>
⏰ $(date '+%d/%m/%Y %H:%M:%S')"
        fi
        
        STATUS=1
        FAILED_SERVICES="$FAILED_SERVICES\n❌ $name"
    fi
}

# Kiểm tra từng service
check_and_restart "MongoDB" \
    "systemctl is-active --quiet mongod" \
    "sudo systemctl start mongod"

check_and_restart "Cowrie SSH" \
    "pgrep -f 'twistd.*cowrie'" \
    "cd ~/Honeypot-Monitor/honeypot/cowrie-src && source cowrie-env/bin/activate && cowrie-env/bin/cowrie start"

check_and_restart "FastAPI" \
    "curl -s http://localhost:8000/" \
    "cd ~/Honeypot-Monitor/parser && source venv/bin/activate && nohup uvicorn main:app --host 127.0.0.1 --port 8000 > /tmp/api.log 2>&1 &"

check_and_restart "Dashboard" \
    "curl -s http://localhost:8080/" \
    "cd ~/Honeypot-Monitor/dashboard && nohup live-server . --port=8080 --host=127.0.0.1 > /tmp/dashboard.log 2>&1 &"

check_and_restart "Realtime Alert" \
    "pgrep -f 'realtime_alert.py'" \
    "cd ~/Honeypot-Monitor/notifier && source venv/bin/activate && nohup python3 realtime_alert.py > /tmp/realtime.log 2>&1 &"

check_and_restart "Daily Report" \
    "pgrep -f 'daily_report.py'" \
    "cd ~/Honeypot-Monitor/notifier && source venv/bin/activate && nohup python3 daily_report.py > /tmp/daily.log 2>&1 &"

check_and_restart "Auto Backup" \
    "pgrep -f 'backup.py'" \
    "cd ~/Honeypot-Monitor/parser && source venv/bin/activate && nohup python3 backup.py > /tmp/backup.log 2>&1 &"

check_and_restart "Weekly Report" \
    "pgrep -f 'weekly_report.py'" \
    "cd ~/Honeypot-Monitor/notifier && source venv/bin/activate && nohup python3 weekly_report.py > /tmp/weekly.log 2>&1 &"

# Gửi Telegram nếu có service chết
if [ $STATUS -eq 1 ]; then
    send_telegram "⚠️ <b>CẢNH BÁO HỆ THỐNG</b>
━━━━━━━━━━━━━━━
Các dịch vụ bị dừng và đã khởi động lại:
$(echo -e $FAILED_SERVICES)
━━━━━━━━━━━━━━━
$([ -n "$RECOVERED_SERVICES" ] && echo -e "Đã khôi phục:$RECOVERED_SERVICES
━━━━━━━━━━━━━━━")
⏰ $(date '+%d/%m/%Y %H:%M:%S')"
    echo "⚠️  Đã gửi cảnh báo Telegram!"
else
    echo "🎉 Tất cả dịch vụ hoạt động bình thường!"
fi

echo "⏰ Kiểm tra lúc: $(date '+%d/%m/%Y %H:%M:%S')"
