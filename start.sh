#!/bin/bash
echo "🚀 Khởi động hệ thống Honeypot Monitor..."

# MongoDB
sudo systemctl start mongod
echo "✅ MongoDB started"

# Cowrie
cd ~/Honeypot-Monitor/honeypot/cowrie-src
source cowrie-env/bin/activate
cowrie-env/bin/cowrie start
echo "✅ Cowrie started"

# FastAPI (chạy nền)
cd ~/Honeypot-Monitor/parser
source venv/bin/activate
nohup uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &
echo "✅ FastAPI started tại http://localhost:8000"

# Dashboard (chạy nền)
cd ~/Honeypot-Monitor/dashboard
nohup live-server . --port=8080 > /tmp/dashboard.log 2>&1 &
echo "✅ Dashboard started tại http://localhost:8080"

# Realtime Alert — lưu DB + gửi Telegram ngay lập tức
cd ~/Honeypot-Monitor/notifier
source venv/bin/activate
nohup python3 realtime_alert.py > /tmp/realtime.log 2>&1 &
echo "✅ Realtime Alert started"

# Daily Report — báo cáo tự động 8h sáng
nohup python3 daily_report.py > /tmp/daily.log 2>&1 &
echo "✅ Daily Report started (8h sáng mỗi ngày)"

echo ""
echo "🎉 Hệ thống đã sẵn sàng!"
echo "📊 Dashboard: http://localhost:8080"
echo "🔌 API:       http://localhost:8000"
echo "📱 Telegram:  Cảnh báo realtime"
echo "📋 Báo cáo:   Tự động 8h sáng"
