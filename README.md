# 🍯 Honeypot Monitor

Hệ thống giám sát và cảnh báo sớm tấn công mạng sử dụng Cowrie Honeypot.

## 📌 Tổng quan

Honeypot Monitor là hệ thống thu thập, phân tích và cảnh báo các cuộc tấn công SSH theo thời gian thực. Hệ thống sử dụng Cowrie Honeypot để giả lập máy chủ SSH, ghi lại toàn bộ hành vi của kẻ tấn công và gửi cảnh báo qua Telegram.

## 🏗️ Kiến trúc hệ thống
Kẻ tấn công → Cowrie Honeypot → Log Parser → MongoDB
↓
Dashboard ← FastAPI ← Realtime Alert → Telegram

## 🚀 Tính năng

- ✅ Thu thập log tấn công SSH realtime
- ✅ Phân tích và lưu trữ vào MongoDB
- ✅ Dashboard web 5 trang: Dashboard, Tấn công, Thống kê, Bản đồ, Tìm kiếm IP
- ✅ Cảnh báo Telegram ngay lập tức (<2 giây)
- ✅ Báo cáo tự động hàng ngày lúc 8h sáng
- ✅ Lệnh bot Telegram: /stats /top /brute /help
- ✅ Bản đồ thế giới hiển thị IP tấn công
- ✅ Export dữ liệu ra CSV
- ✅ Auto cleanup log cũ hơn 30 ngày
- ✅ Healthcheck tự động restart service

## 🛠️ Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Honeypot | Cowrie SSH Honeypot |
| Backend | FastAPI + Python |
| Database | MongoDB |
| Frontend | HTML/CSS/JavaScript |
| Bản đồ | Leaflet.js + OpenStreetMap |
| Cảnh báo | Telegram Bot API |
| GeoIP | MaxMind GeoLite2 |

## 👥 Thành viên nhóm

| Thành viên | Vai trò | Chức năng |
|---|---|---|
| TV1 | Honeypot | Cowrie setup, bản đồ, healthcheck |
| TV2 | Backend | FastAPI, MongoDB, GeoIP |
| TV3 | Frontend | Dashboard 5 trang, Export CSV |
| TV4 | Alerting | Telegram Bot, realtime alert |

## ⚙️ Cài đặt

### Yêu cầu
- Ubuntu 20.04/22.04 hoặc WSL
- Python 3.10+
- Node.js + npm
- MongoDB 6.0+

### Clone và cài đặt

```bash
# Clone repo
git clone https://github.com/fhafqi3uq/Honeypot-Monitor.git
cd Honeypot-Monitor

# Tạo file .env
cat > notifier/.env << 'ENV'
TELEGRAM_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
ABUSEIPDB_KEY=your_abuseipdb_key
ENV

# Setup lần đầu
bash setup.sh

# Khởi động hệ thống
bash start.sh
```

## 📊 API Endpoints

| Endpoint | Mô tả |
|---|---|
| GET /api/stats | Thống kê tổng hợp |
| GET /api/attacks | Danh sách tấn công |
| GET /api/top-ips | Top IP tấn công |
| GET /api/top-passwords | Top password bị thử |
| GET /api/top-usernames | Top username bị thử |
| GET /api/brute-force | Phát hiện brute-force |
| GET /api/map-data | Dữ liệu bản đồ |
| GET /api/search?ip= | Tìm kiếm theo IP |
| GET /api/export/csv | Xuất CSV |
| GET /api/stats/hourly | Thống kê theo giờ |
| GET /api/stats/countries | Top quốc gia |

## 🤖 Lệnh Telegram Bot

| Lệnh | Chức năng |
|---|---|
| /stats | Thống kê tổng hợp |
| /top | Top 5 IP tấn công |
| /brute | 5 lần thử gần nhất |
| /help | Danh sách lệnh |

## 📁 Cấu trúc thư mục
Honeypot-Monitor/
├── dashboard/          # Frontend 5 trang
│   ├── index.html      # Dashboard chính
│   ├── attacks.html    # Danh sách tấn công
│   ├── stats.html      # Thống kê
│   ├── map.html        # Bản đồ thế giới
│   ├── search.html     # Tìm kiếm IP
│   ├── css/style.css   # Giao diện
│   └── js/             # JavaScript
├── honeypot/           # Cowrie config
├── notifier/           # Telegram Bot
│   ├── bot.py          # Bot chính
│   ├── realtime_alert.py # Cảnh báo realtime
│   ├── daily_report.py # Báo cáo ngày
│   └── telegram_commands.py # Lệnh bot
├── parser/             # Backend API
│   ├── main.py         # FastAPI endpoints
│   ├── parser.py       # Log parser
│   └── cleanup.py      # Auto cleanup
├── healthcheck.sh      # Kiểm tra hệ thống
├── setup.sh            # Cài đặt lần đầu
└── start.sh            # Khởi động hệ thống
