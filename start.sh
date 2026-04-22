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

# FastAPI
cd "$PROJECT_DIR/parser"
source venv/bin/activate
nohup uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &
echo "✅ FastAPI started tại http://localhost:8000"

# Dashboard
cd "$PROJECT_DIR/dashboard"
nohup live-server . --port=8080 > /tmp/dashboard.log 2>&1 &
echo "✅ Dashboard started tại http://localhost:8080"

# Realtime Alert
cd "$PROJECT_DIR/notifier"
source venv/bin/activate
nohup python3 realtime_alert.py > /tmp/realtime.log 2>&1 &
echo "✅ Realtime Alert started"

# Daily Report
nohup python3 daily_report.py > /tmp/daily.log 2>&1 &
echo "✅ Daily Report started (8h sáng mỗi ngày)"

# Auto cleanup
cd "$PROJECT_DIR/parser"
source venv/bin/activate
nohup python3 cleanup.py > /tmp/cleanup.log 2>&1 &
echo "✅ Auto cleanup started (xoá log >30 ngày lúc 00:00)"

# Telegram Commands Bot
cd "$PROJECT_DIR/notifier"
source venv/bin/activate
nohup python3 telegram_commands.py > /tmp/commands.log 2>&1 &
echo "✅ Telegram Commands started (/stats /top /brute /help)"

echo ""
echo "🎉 Hệ thống đã sẵn sàng!"
echo "📊 Dashboard: http://localhost:8080"
echo "🔌 API:       http://localhost:8000"
echo "📱 Telegram:  Cảnh báo realtime"
echo "📋 Báo cáo:   Tự động 8h sáng"
