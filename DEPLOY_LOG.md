# Nhật ký triển khai VPS — theo dõi tiến độ `GO_LIVE.md`

Ghi lại để không mất tiến độ giữa các phiên làm việc. Không chứa mật khẩu/private
key thật — chỉ chứa thông tin cấu hình cần nhớ.

## Hạ tầng

- **Nhà cung cấp**: CloudFly (`my.cloudfly.vn`), gói **Dùng thử 3 ngày**
- **Instance**: `instance_53657340`
- **IP public**: `222.255.182.122`
- **Vị trí**: Việt Nam 04
- **Cấu hình**: 1 CPU / 1GB RAM / 20GB SSD, Ubuntu 24.04 64bit
- **Hết hạn trial**: 07:00 08-08-2026 — **cần nâng cấp lên gói trả phí trước mốc
  này** nếu muốn giữ máy chạy tiếp, không thì bị xoá cùng dữ liệu.
- **RAM chỉ 1GB** → khi chạy Docker Compose, **bỏ Prometheus + Grafana** ra khỏi
  stack (chỉ chạy `mongo` + `parser-*` + `notifier-*` + `dashboard`), theo đúng
  lưu ý RAM thấp trong `GO_LIVE.md`.

## SSH — đã hoàn tất (Phần 2 + 3 của `GO_LIVE.md`)

- User quản trị: **`honeypotadmin`** (có quyền `sudo`) — không dùng `root` trực
  tiếp nữa.
- Cổng SSH thật: **`2200`** (đổi khỏi 22 để nhường cho Cowrie).
- Đăng nhập bằng **SSH key only** — `PasswordAuthentication no`,
  `PermitRootLogin no` đã bật trên VPS.
- Private key: `sshkey-88735220.pem`, do CloudFly tự sinh, đang lưu ở
  `E:\sshkey-88735220.pem` trên máy Windows — **giữ nguyên tại đó, không đưa
  vào repo/Git dưới bất kỳ hình thức nào.**
- Lệnh kết nối chuẩn từ giờ:
  ```powershell
  ssh -i "E:\sshkey-88735220.pem" -p 2200 honeypotadmin@222.255.182.122
  ```

### Vướng mắc đã gặp và cách xử lý (để không lặp lại lỗi)

1. **Ubuntu dùng `ssh.socket` (systemd socket activation)** — cổng trong
   `sshd_config` (`Port 2200`) bị `ssh.socket` ghi đè, vẫn nghe ở cổng 22 dù
   config đã đúng. Fix: `sudo systemctl stop ssh.socket && sudo systemctl
   disable ssh.socket && sudo systemctl restart ssh.service`.
2. **File `/etc/ssh/sshd_config.d/50-cloud-init.conf` và
   `01-permitrootlogin.conf`** override `PasswordAuthentication`/
   `PermitRootLogin` trong file `sshd_config` chính (do `Include` xử lý trước).
   Phải sửa trực tiếp 2 file đó, sửa file chính không có tác dụng.
3. **Windows OpenSSH từ chối private key** nếu file cho phép `NT
   AUTHORITY\Authenticated Users` hoặc `BUILTIN\Users` đọc được — chỉ được để
   lại quyền cho user hiện tại + `Administrators` + `SYSTEM`:
   ```powershell
   icacls "E:\sshkey-88735220.pem" /remove "NT AUTHORITY\Authenticated Users"
   icacls "E:\sshkey-88735220.pem" /remove "BUILTIN\Users"
   ```

## Firewall (ufw) — đã hoàn tất (Phần 3)

```
Status: active
Default: deny (incoming), allow (outgoing)
2200/tcp  ALLOW IN  Anywhere   # admin ssh (real)
22/tcp    ALLOW IN  Anywhere   # cowrie honeypot
```

## Đã xong — code repo (Phần 1)

- Repo đã có remote GitHub sẵn (`git@github.com:fhafqi3uq/Honeypot-Monitor.git`).
- 2026-08-05: commit `0aaf9c0a` (MITRE ATT&CK mapping + GO_LIVE.md +
  `deploy/` scripts + DEPLOY_LOG.md) đã push lên `origin/main`. Toàn bộ
  pytest liên quan (`test_mitre_mapping.py`, `test_parser.py`, `test_api.py`,
  `test_alerting.py` — 161 test) pass trước khi push.
- Bước kế tiếp trên VPS: `git clone git@github.com:fhafqi3uq/Honeypot-Monitor.git`
  (cần deploy key hoặc HTTPS + PAT trên VPS, vì đây là private-key-based
  clone — VPS chưa có key riêng để pull từ GitHub).

## Chưa làm — bước tiếp theo

2. Cài Cowrie native trên VPS (`SETUP.md` bước 3), xác nhận nó lắng nghe ở
   `2222` nội bộ.
3. NAT cổng 22 công khai → 2222 (Cowrie) — `deploy/expose_cowrie_port22.sh`.
4. Xác minh từ máy khác: `ssh -p 22 root@222.255.182.122` phải thấy banner
   Cowrie giả (`svr04`), không phải sshd thật.
5. Sinh secrets thật trên VPS (`deploy/generate_prod_secrets.sh`), rồi
   `docker compose up -d --build` (bỏ Prometheus/Grafana do RAM 1GB).
6. Test dashboard/API qua SSH tunnel (cổng 2200), không public.
