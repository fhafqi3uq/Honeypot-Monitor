#!/bin/bash

NOTIFIER_DIR=~/Honeypot-Monitor/notifier
STATUS=0
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
        eval "$restart_cmd"
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
    "cd ~/Honeypot-Monitor/parser && source venv/bin/activate && nohup uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &"

check_and_restart "Dashboard" \
    "curl -s http://localhost:8080/" \
    "cd ~/Honeypot-Monitor/dashboard && nohup live-server . --port=8080 > /tmp/dashboard.log 2>&1 &"

check_and_restart "Realtime Alert" \
    "pgrep -f 'realtime_alert.py'" \
    "cd ~/Honeypot-Monitor/notifier && source venv/bin/activate && nohup python3 realtime_alert.py > /tmp/realtime.log 2>&1 &"

check_and_restart "Daily Report" \
    "pgrep -f 'daily_report.py'" \
    "cd ~/Honeypot-Monitor/notifier && source venv/bin/activate && nohup python3 daily_report.py > /tmp/daily.log 2>&1 &"

# Gửi Telegram nếu có service chết
if [ $STATUS -eq 1 ]; then
    send_telegram "⚠️ <b>CẢNH BÁO HỆ THỐNG</b>
━━━━━━━━━━━━━━━
Các dịch vụ bị dừng và đã khởi động lại:
$(echo -e $FAILED_SERVICES)
━━━━━━━━━━━━━━━
⏰ $(date '+%d/%m/%Y %H:%M:%S')"
    echo "⚠️  Đã gửi cảnh báo Telegram!"
else
    echo "🎉 Tất cả dịch vụ hoạt động bình thường!"
fi

echo "⏰ Kiểm tra lúc: $(date '+%d/%m/%Y %H:%M:%S')"
