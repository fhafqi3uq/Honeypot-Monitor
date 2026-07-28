#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🚀 Khởi động hệ thống Honeypot Monitor..."
echo "📁 Project: $PROJECT_DIR"

# MongoDB
sudo systemctl start mongod
echo "✅ MongoDB started"

# Cowrie
cd "$PROJECT_DIR/honeypot/cowrie-src"
source cowrie-env/bin/activate
cowrie-env/bin/cowrie start
echo "✅ Cowrie started"

# FastAPI (bind localhost only — API không xác thực, không được lộ ra cùng
# interface public với honeypot, nếu không attacker port-scan sẽ thấy ngay
# đây là hệ thống có giám sát)
cd "$PROJECT_DIR/parser"
source venv/bin/activate
nohup uvicorn main:app --host 127.0.0.1 --port 8000 > /tmp/api.log 2>&1 &
echo "✅ FastAPI started tại http://localhost:8000 (chỉ nội bộ)"

# Dashboard (bind localhost only — cùng lý do như FastAPI ở trên)
cd "$PROJECT_DIR/dashboard"
nohup live-server . --port=8080 --host=127.0.0.1 > /tmp/dashboard.log 2>&1 &
echo "✅ Dashboard started tại http://localhost:8080 (chỉ nội bộ)"

# Realtime Alert
cd "$PROJECT_DIR/notifier"
source venv/bin/activate
pkill -f realtime_alert.py 2>/dev/null; sleep 3 && nohup python3 -u realtime_alert.py > /tmp/realtime.log 2>&1 &
echo "✅ Realtime Alert started"

# Daily Report
pkill -f daily_report.py 2>/dev/null; nohup python3 -u daily_report.py > /tmp/daily.log 2>&1 &
echo "✅ Daily Report started (8h sáng mỗi ngày)"

# Auto cleanup
cd "$PROJECT_DIR/parser"
source venv/bin/activate
pkill -f cleanup.py 2>/dev/null; nohup python3 -u cleanup.py > /tmp/cleanup.log 2>&1 &
echo "✅ Auto cleanup started (xoá log >30 ngày lúc 00:00)"

# Telegram Commands Bot
cd "$PROJECT_DIR/notifier"
source venv/bin/activate
pkill -f telegram_commands.py 2>/dev/null; nohup python3 -u telegram_commands.py > /tmp/commands.log 2>&1 &
echo "✅ Telegram Commands started (/stats /top /brute /help)"

# Healthcheck mỗi 30 giây
pkill -f "while true.*healthcheck" 2>/dev/null
nohup bash -c 'while true; do bash $PROJECT_DIR/healthcheck.sh >> /tmp/healthcheck.log 2>&1; sleep 30; done' > /dev/null 2>&1 &
echo "✅ Healthcheck started (mỗi 30 giây)"

echo ""
echo "🎉 Hệ thống đã sẵn sàng!"
echo "📊 Dashboard: http://localhost:8080"
echo "🔌 API:       http://localhost:8000"
echo "📱 Telegram:  Cảnh báo realtime"
echo "📋 Báo cáo:   Tự động 8h sáng"
