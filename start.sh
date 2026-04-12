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

echo ""
echo "🎉 Hệ thống đã sẵn sàng!"
echo "📊 Dashboard: http://localhost:8080"
echo "🔌 API:       http://localhost:8000"
