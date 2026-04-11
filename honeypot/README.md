# 🪤 Cowrie Honeypot Setup

## Mục đích
Thu thập và giám sát các cuộc tấn công SSH/Telnet bằng cách giả lập server vulnerable.

## Cấu trúc thư mục

```
honeypot/
├── setup.sh          # Script tự động cài đặt Cowrie
├── README.md         # File này
├── sample_log.json   # Dữ liệu log mẫu (cho team test)
└── cowrie.cfg        # Config (copy từ Cowrie repo)
```

## Cách cài đặt nhanh

```bash
# Clone repo
git clone https://github.com/fhafqi3uq/Honeypot-Monitor.git
cd Honeypot-Monitor/honeypot

# Chạy setup script
chmod +x setup.sh
./setup.sh
```

## Cách chạy Cowrie

```bash
# 1. Activate virtualenv
source /home/cowrie/cowrie/cowrie-env/bin/activate

# 2. Start Cowrie
/home/cowrie/cowrie/cowrie-env/bin/cowrie start

# 3. Kiểm tra trạng thái
/home/cowrie/cowrie/cowrie-env/bin/cowrie status
```

## Đọc log

Cowrie ghi log ra 2 file:

| File | Định dạng | Đường dẫn |
|------|-----------|------------|
| `cowrie.json` | JSON (1 dòng/event) | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| `cowrie.log` | Text (human readable) | `/home/cowrie/cowrie/var/log/cowrie/cowrie.log` |

```bash
# Xem log real-time
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json

# Xem log text
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log
```

## Các eventid quan trọng

| Event ID | Mô tả |
|----------|-------|
| `cowrie.session.connect` | SSH connection mới |
| `cowrie.login.success` | Login thành công |
| `cowrie.login.failed` | Login thất bại |
| `cowrie.command.input` | Command được nhập |
| `cowrie.session.closed` | Session đóng |

## SSH vào honeypot (để test)

```bash
# Từ terminal khác hoặc máy khác
ssh -p 2222 root@<IP_cua_may_chay_cowrie>

# Password: bất kỳ (Cowrie chấp nhận mọi password)
```

## Các port mặc định

| Port | Protocol | Mô tả |
|------|----------|-------|
| 2222 | SSH | Honeypot SSH |
| 2223 | Telnet | Honeypot Telnet (nếu bật) |

## Phân tích log JSON

Các trường trong log:

```json
{
  "eventid": "cowrie.login.failed",
  "src_ip": "203.0.113.45",
  "username": "admin",
  "password": "password123",
  "session": "abc123def456",
  "timestamp": "2026-04-11T18:53:30.654321Z"
}
```

## Kết nối với các module khác

- **TV2 (Parser):** Đọc log từ `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`
- **TV3 (Dashboard):** Lấy data từ API của TV2
- **TV4 (Notifier):** Alert khi phát hiện brute-force

## Troubleshooting

```bash
# Xem Cowrie đang chạy không
ps aux | grep cowrie

# Restart Cowrie
/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
/home/cowrie/cowrie/cowrie-env/bin/cowrie start

# Xem log lỗi
cat /home/cowrie/cowrie/var/log/cowrie/cowrie.log | tail -50
```

## Liên hệ

- **TV1 (Quang):** Cài đặt & config Cowrie
- **GitHub Repo:** https://github.com/fhafqi3uq/Honeypot-Monitor