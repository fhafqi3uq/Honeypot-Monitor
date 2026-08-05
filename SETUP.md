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
sudo apt-get update && sudo apt-get install -y mongodb-org mongodb-database-tools
sudo systemctl start mongod
sudo systemctl enable mongod
```
`mongodb-database-tools` (gói riêng, không còn bundle sẵn trong `mongodb-org`
từ MongoDB 6+) cung cấp lệnh `mongodump` mà `parser/backup.py` cần — thiếu
gói này thì auto-backup vẫn chạy, chỉ tự log lỗi mỗi lần thay vì tạo được
bản backup.

---

## Bước 3 — TV1: Cài Cowrie
```bash
cd honeypot
git clone https://github.com/cowrie/cowrie.git cowrie-src
cd cowrie-src
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
pip install -e .   # đăng ký lệnh `cowrie` (project.scripts trong pyproject.toml) -
                    # requirements.txt chỉ pin dependency, không tự cài chính package
cp ../cowrie.cfg etc/cowrie.cfg

# Overlay giả lập hệ thống thật (bash history, ví crypto giả, DB dump giả,
# web app giả, log giả...) - honeyfs/ chỉ cấp NỘI DUNG file, còn phải có
# entry tương ứng trong fs.pickle thì `ls`/`cat` mới thấy được (xem
# honeypot/README-honeyfs.md nếu có thắc mắc tại sao cần cả 2 bước này).
cp -r ../honeyfs-overlay/. honeyfs/
cp ../fs.pickle src/cowrie/data/fs.pickle

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

# Chạy API - LUÔN bind 127.0.0.1, không phải 0.0.0.0: API không có gì chặn
# port-scan nếu bind ra ngoài, sẽ lộ ngay cho attacker biết đây là hệ thống
# có giám sát. Nếu cần truy cập dashboard/API từ xa, dùng SSH tunnel/VPN,
# không mở port này ra internet trực tiếp (xem GO_LIVE.md ở gốc repo).
uvicorn main:app --host 127.0.0.1 --port 8000

# Chạy log watcher realtime
nohup python3 log_watcher.py > /tmp/log_watcher.log 2>&1 &
```

---

## Bước 5 — TV3: Cài Dashboard
```bash
sudo npm install -g live-server
cd ~/Honeypot-Monitor/dashboard
# --host=127.0.0.1 bắt buộc - live-server mặc định bind mọi interface,
# sẽ lộ dashboard ra internet nếu chạy trên VPS public.
live-server . --port=8080 --host=127.0.0.1
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

## Cách khác: chạy bằng Docker Compose

`docker-compose.yml` ở gốc repo container hoá MongoDB + parser/ + notifier/ +
dashboard/ — **không gồm Cowrie**, Cowrie vẫn chạy native như Bước 3 ở trên
(container hoá Twisted reactor bind port thấp + submodule không push phức
tạp hơn nhiều, không đáng để làm chung đợt này).

```bash
# 1. Cowrie phải chạy native TRƯỚC (để file log cowrie.json tồn tại) -
#    parser-log-watcher/notifier-realtime-alert stat() file này lúc khởi
#    động, sẽ crash-loop (vô hại, restart: unless-stopped tự thử lại) tới
#    khi file xuất hiện.
cd honeypot/cowrie-src && source cowrie-env/bin/activate && cowrie-env/bin/cowrie start && cd ../..

# 2. Tạo .env cho parser/ và notifier/ (chỉ cần MONGO_URL/DB_NAME/DASHBOARD_ORIGIN
#    khi chạy Docker - secrets thật đi qua bước 2b bên dưới, không qua .env)
cp parser/.env.example parser/.env
cp notifier/.env.example notifier/.env

# 2b. Tạo secrets/ (bắt buộc - xem secrets/README.md để biết chi tiết từng file)
mkdir -p secrets
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/jwt_secret_key.txt
echo -n "<TELEGRAM_TOKEN của bạn>"   > secrets/telegram_token.txt
echo -n "<TELEGRAM_CHAT_ID của bạn>" > secrets/telegram_chat_id.txt
echo -n "<ABUSEIPDB_KEY của bạn>"    > secrets/abuseipdb_key.txt   # để trống file cũng được

# Mật khẩu MongoDB (2 tài khoản) - chỉ có tác dụng lúc mongo container
# khởi động LẦN ĐẦU với volume dữ liệu rỗng (đổi sau này không có tác dụng
# trừ khi `docker compose down -v` - LỆNH NÀY XOÁ SẠCH DỮ LIỆU trong mongo_data).

# 1. Tài khoản ROOT - chỉ dùng cho việc quản trị (backup, mongosh thủ công,
#    mongodb-exporter). Không app service nào dùng tài khoản này.
echo -n "honeypot_root" > secrets/mongo_username.txt
python3 -c "import secrets; print(secrets.token_urlsafe(24))" > secrets/mongo_password.txt

# 2. Tài khoản APP (least-privilege) - mongo-init/create-app-user.sh tự tạo
#    tài khoản này với quyền readWrite CHỈ trên database "honeypot" (không
#    phải root) - đây mới là tài khoản mà parser-api/log-watcher/cleanup/
#    realtime-alert/telegram-commands thực sự dùng để kết nối.
echo -n "honeypot_app" > secrets/mongo_app_username.txt
python3 -c "import secrets; print(secrets.token_urlsafe(24))" > secrets/mongo_app_password.txt

# mongodb-exporter không hỗ trợ kiểu file secret như trên (giới hạn của
# chính công cụ đó) - cần 1 file .env riêng chứa plaintext (vẫn gitignore).
# Dùng tài khoản ROOT ở đây (không phải app) vì --collector.diagnosticdata
# cần quyền clusterMonitor, rộng hơn readWrite trên 1 database:
cat > secrets/mongodb_exporter.env <<EOF
MONGODB_USER=$(cat secrets/mongo_username.txt)
MONGODB_PASSWORD=$(cat secrets/mongo_password.txt)
EOF

# 3. Tải GeoIP database vào parser/geoip/ (giống Bước 4) nếu chưa có

# 4. Build và chạy - mặc định KHÔNG gồm Prometheus/Grafana/mongodb-exporter
#    (profiles: ["observability"] trong docker-compose.yml) vì trên VPS nhỏ
#    (1 CPU/1GB RAM) chạy cả 11 container cùng lúc dễ treo máy (gặp thật khi
#    triển khai VPS trial - xem DEPLOY_LOG.md). Máy đủ mạnh (>=2GB RAM) muốn
#    có Prometheus/Grafana thì thêm --profile observability vào lệnh dưới.
docker compose up -d --build

# API:        http://localhost:8000 (127.0.0.1 only)
# Dashboard:  http://localhost:8080 (127.0.0.1 only)
#
# Muốn thêm Prometheus/Grafana (cần >=2GB RAM):
#   docker compose --profile observability up -d --build
# Prometheus: http://localhost:9090 (127.0.0.1 only) - theo dõi cả parser-api
#             lẫn 5 script nền (log_watcher/cleanup/realtime_alert/
#             daily_report/telegram_commands), mỗi cái tự expose /metrics riêng.
# Grafana:    http://localhost:3000 (127.0.0.1 only) - đăng nhập admin/admin
#             (đổi ngay, hoặc set GRAFANA_ADMIN_PASSWORD trước khi lên) -
#             dashboard "Honeypot Monitor - Overview" đã tự nạp sẵn.
```

Ghi chú: MongoDB trong Compose **đã bật authentication** (khác với mongod
native, vẫn không cần auth vì chỉ bind `127.0.0.1` — 2 cách chạy có 2 mức
bảo mật khác nhau, đây là điểm khác biệt chính giữa chúng), và đã
**least-privilege** (2 tài khoản, không dùng chung 1 root nữa):

- Tài khoản **root** (`secrets/mongo_username.txt`/`mongo_password.txt`) —
  chỉ dùng cho quản trị (backup, mongosh thủ công, mongodb-exporter).
- Tài khoản **app** (`secrets/mongo_app_username.txt`/`mongo_app_password.txt`)
  — do `mongo-init/create-app-user.sh` tự tạo, chỉ có quyền `readWrite`
  trên đúng database `honeypot`. Đây là tài khoản mà `parser-api`,
  `parser-log-watcher`, `parser-cleanup`, `notifier-realtime-alert`, và
  `notifier-telegram-commands` thực sự dùng để kết nối — nếu container nào
  trong số này bị chiếm quyền, kẻ tấn công cũng không đụng được database
  hay lệnh admin khác.

Cả hai đều chỉ được tạo 1 lần duy nhất lúc `mongo` container khởi động lần
đầu với volume rỗng — đổi file secret sau đó không có tác dụng trừ khi chạy
`docker compose down -v` (XOÁ SẠCH DỮ LIỆU). Đã kiểm chứng bằng container
Docker thật (không chỉ đọc YAML): tài khoản app tạo đúng, chỉ `readWrite`
trên `honeypot` (thử ghi vào database khác bị từ chối), `parser-api` kết
nối/login được bình thường qua tài khoản app, `mongodb-exporter` vẫn hoạt
động qua tài khoản root không đổi. Nếu tính triển khai VPS public thật, đây
là bước đã sẵn sàng, không cần làm thêm gì cho phần Mongo auth.

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
