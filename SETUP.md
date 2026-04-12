# Hướng dẫn cài đặt từ đầu

## Yêu cầu hệ thống
- Ubuntu 20.04+
- Python 3.10+
- Node.js 20+
- MongoDB 7.0

---

## Bước 1 — Clone repo
```bash
git clone https://github.com/fhafqi3uq/Honeypot-Monitor.git
cd Honeypot-Monitor
```

---

## Bước 2 — Cài MongoDB
```bash
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get update && sudo apt-get install -y mongodb-org
sudo systemctl start mongod
sudo systemctl enable mongod
```

---

## Bước 3 — TV1: Cài Cowrie
```bash
cd honeypot
git clone https://github.com/cowrie/cowrie.git cowrie-src
cd cowrie-src
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
cp ../cowrie.cfg etc/cowrie.cfg
cowrie-env/bin/cowrie start
```

---

## Bước 4 — TV2: Cài Backend
```bash
cd ~/Honeypot-Monitor/parser
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Tải GeoIP database
mkdir -p geoip
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb -O geoip/GeoLite2-City.mmdb

# Import log mẫu vào MongoDB
python parser.py

# Chạy API
uvicorn main:app --host 0.0.0.0 --port 8000

# Chạy log watcher realtime
nohup python3 log_watcher.py > /tmp/log_watcher.log 2>&1 &
```

---

## Bước 5 — TV3: Cài Dashboard
```bash
sudo npm install -g live-server
cd ~/Honeypot-Monitor/dashboard
live-server . --port=8080
# Mở trình duyệt: http://localhost:8080
```

---

## Bước 6 — TV4: Cài Telegram Bot
```bash
cd ~/Honeypot-Monitor/notifier
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Tạo file .env
cp .env.example .env
nano .env
# Điền TELEGRAM_TOKEN và TELEGRAM_CHAT_ID vào

# Chạy watcher tự động
nohup python3 watcher.py > /tmp/watcher.log 2>&1 &
```

---

## Chạy toàn bộ hệ thống (sau khi đã setup xong)
```bash
bash ~/Honeypot-Monitor/start.sh
```

---

## Kiểm tra hệ thống
```bash
# Cowrie
cd ~/Honeypot-Monitor/honeypot/cowrie-src
cowrie-env/bin/cowrie status

# MongoDB
sudo systemctl status mongod

# API
curl http://localhost:8000/api/stats

# Dashboard
# Mở trình duyệt: http://localhost:8080

# Log watcher
tail -f /tmp/log_watcher.log

# Watcher bot
tail -f /tmp/watcher.log
```
