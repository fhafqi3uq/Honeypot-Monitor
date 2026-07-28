# 🍯 Honeypot Monitor

Hệ thống giám sát và cảnh báo sớm tấn công mạng sử dụng Cowrie Honeypot.

## 📌 Tổng quan

Honeypot Monitor thu thập, phân tích và cảnh báo các cuộc tấn công SSH theo thời gian thực. Cowrie Honeypot giả lập máy chủ SSH, ghi lại hành vi kẻ tấn công và gửi cảnh báo qua Telegram.

## 🚀 Tính năng

- ✅ Thu thập log tấn công SSH realtime
- ✅ Dashboard web 5 trang: Dashboard, Tấn công, Thống kê, Bản đồ, Tìm kiếm IP
- ✅ Cảnh báo Telegram ngay lập tức dưới 2 giây
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

**Yêu cầu:** Ubuntu 20.04/22.04, Python 3.10+, Node.js, MongoDB 6.0+

```bash
git clone https://github.com/fhafqi3uq/Honeypot-Monitor.git
cd Honeypot-Monitor
bash setup.sh
bash start.sh
```

## 🔐 Đăng nhập Dashboard

Dashboard và toàn bộ `/api/*` đều yêu cầu đăng nhập (JWT qua cookie httpOnly) - đây là dữ liệu honeypot (IP, username/password kẻ tấn công dùng, geo...), không nên để bất kỳ ai truy cập được dù server chỉ bind localhost.

### Tạo tài khoản admin đầu tiên

```bash
cd parser
source venv/bin/activate

# 1. Tạo secret key cho JWT (bắt buộc, không có giá trị mặc định)
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"
# dán chuỗi in ra vào .env: JWT_SECRET_KEY=<chuỗi vừa tạo>

# 2. Tạo tài khoản (hỏi username/password qua prompt, không hardcode)
python3 create_admin.py
```

Chạy lại `create_admin.py` bất cứ lúc nào để tạo thêm admin khác hoặc đổi mật khẩu (script sẽ hỏi xác nhận nếu username đã tồn tại).

### Đăng nhập lần đầu

1. `bash start.sh` (hoặc chạy riêng uvicorn + live-server)
2. Mở `http://localhost:8080/login.html`, nhập username/password vừa tạo
3. Đăng nhập thành công sẽ chuyển vào `index.html`; nút "🚪 Đăng xuất" ở sidebar mọi trang

### Cơ chế hoạt động (tóm tắt)

- **Password**: hash bằng bcrypt (`parser/auth.py`), không bao giờ lưu/so sánh plaintext.
- **JWT**: `access_token` sống ngắn (90 phút) dùng cho mọi request; `refresh_token` sống dài (7 ngày), được lưu trong Mongo (`refresh_tokens`) để có thể thu hồi - đây chính là cơ chế "blacklist": logout hoặc mỗi lần gọi `/auth/refresh` sẽ xoá/luân chuyển (rotate) token cũ, nên token bị đánh cắp sau khi rotate sẽ không dùng lại được. Access token thì không tra DB (stateless) nên không có blacklist riêng - đổi lại là cửa sổ rủi ro nếu bị lộ chỉ tối đa 90 phút.
- **Cookie**: cả hai token đều `httpOnly` (JS không đọc được → chống XSS đánh cắp token). Kèm theo 1 cookie `csrf_token` không-httpOnly cho cơ chế CSRF double-submit: mọi request có thay đổi trạng thái (logout, refresh) phải gửi kèm header `X-CSRF-Token` khớp với cookie này.
- **Rate limit chống brute-force**: sai 5 lần trong 15 phút (theo cặp IP+username, lưu trong Mongo `login_attempts`) sẽ khoá 15 phút - tồn tại qua cả việc restart API. Thông báo lỗi đăng nhập luôn chung chung ("Sai thông tin đăng nhập"), không tiết lộ sai username hay sai password.
- **Log đăng nhập**: mọi lần đăng nhập (thành công lẫn thất bại) được ghi vào Mongo `auth_log` (IP, username, thời gian, user-agent) - áp dụng đúng nguyên lý honeypot đang dạy: tự giám sát cửa trước của chính mình.
- **Giới hạn kiến trúc cần biết**: dashboard được serve tĩnh qua `live-server` (không chạy Python), nên việc "chặn truy cập trang HTML" chỉ thực hiện được ở phía client (JS kiểm tra session, redirect sang `login.html` nếu chưa đăng nhập) - ranh giới bảo mật thật sự nằm ở FastAPI (mọi `/api/*` đều bị chặn ở backend nếu không có token hợp lệ), không phải ở file HTML tĩnh.

## 📊 API Endpoints

Tất cả endpoint `/api/*` bên dưới đều yêu cầu đã đăng nhập (cookie `access_token` hợp lệ) - gọi trực tiếp mà không có cookie sẽ trả về `401`. Chỉ `GET /` là public (health check, không có dữ liệu nhạy cảm).

| Endpoint | Mô tả | Yêu cầu đăng nhập |
|---|---|---|
| POST /auth/login | Đăng nhập, trả JWT qua cookie | Không |
| POST /auth/logout | Đăng xuất, thu hồi refresh token | Có (+ CSRF) |
| POST /auth/refresh | Cấp access token mới từ refresh token | Có (+ CSRF) |
| GET /auth/me | Kiểm tra session hiện tại | Có |
| GET /api/stats | Thống kê tổng hợp | Có |
| GET /api/attacks | Danh sách tấn công | Có |
| GET /api/top-ips | Top IP tấn công | Có |
| GET /api/top-passwords | Top password bị thử | Có |
| GET /api/top-usernames | Top username bị thử | Có |
| GET /api/brute-force | Phát hiện brute-force | Có |
| GET /api/map-data | Dữ liệu bản đồ | Có |
| GET /api/search?ip= | Tìm kiếm theo IP | Có |
| GET /api/export/csv | Xuất CSV | Có |
| GET /api/stats/hourly | Thống kê theo giờ | Có |
| GET /api/stats/countries | Top quốc gia | Có |

## 🤖 Lệnh Telegram Bot

| Lệnh | Chức năng |
|---|---|
| /stats | Thống kê tổng hợp |
| /top | Top 5 IP tấn công |
| /brute | 5 lần thử gần nhất |
| /help | Danh sách lệnh |

## 📁 Cấu trúc thư mục

    Honeypot-Monitor/
    ├── dashboard/
    │   ├── index.html
    │   ├── attacks.html
    │   ├── stats.html
    │   ├── map.html
    │   ├── search.html
    │   ├── login.html
    │   ├── css/style.css
    │   └── js/ (data.js, auth.js, charts.js, app.js)
    ├── honeypot/
    ├── notifier/
    │   ├── bot.py
    │   ├── realtime_alert.py
    │   ├── daily_report.py
    │   └── telegram_commands.py
    ├── parser/
    │   ├── main.py
    │   ├── auth.py
    │   ├── create_admin.py
    │   ├── parser.py
    │   └── cleanup.py
    ├── healthcheck.sh
    ├── setup.sh
    └── start.sh
