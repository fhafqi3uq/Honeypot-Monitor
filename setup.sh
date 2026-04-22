#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🔧 Cài đặt lần đầu..."

# Xoá data cũ
mongosh --eval "db.getSiblingDB('honeypot').attacks.drop()" 2>/dev/null
echo "✅ Database đã được reset về 0"

# Cài thư viện
cd "$PROJECT_DIR/parser"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -q
echo "✅ Parser dependencies installed"

cd "$PROJECT_DIR/notifier"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -q
echo "✅ Notifier dependencies installed"

echo "🎉 Setup xong! Chạy: bash start.sh"
