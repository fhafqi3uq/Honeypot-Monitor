# Nhật ký triển khai VPS — theo dõi tiến độ `GO_LIVE.md`

Ghi lại để không mất tiến độ giữa các phiên làm việc. Không chứa mật khẩu/private
key thật — chỉ chứa thông tin cấu hình cần nhớ. IP/cổng SSH admin/instance ID
thật đã thay bằng placeholder (`<VPS_IP>`, `<ADMIN_SSH_PORT>`) vì repo này
public — giá trị thật giữ ở `DEPLOY_LOG.local.md` (gitignored, không push).

## Hạ tầng

- **Nhà cung cấp**: CloudFly (`my.cloudfly.vn`), gói **Dùng thử 3 ngày**
- **Instance**: `<INSTANCE_ID>` (giá trị thật ở `DEPLOY_LOG.local.md`)
- **IP public**: `<VPS_IP>` (giá trị thật ở `DEPLOY_LOG.local.md`)
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
- Cổng SSH thật: **`<ADMIN_SSH_PORT>`** (đổi khỏi 22 để nhường cho Cowrie; giá
  trị thật ở `DEPLOY_LOG.local.md`).
- Đăng nhập bằng **SSH key only** — `PasswordAuthentication no`,
  `PermitRootLogin no` đã bật trên VPS.
- Private key: `sshkey-88735220.pem`, do CloudFly tự sinh, đang lưu ở
  `E:\sshkey-88735220.pem` trên máy Windows — **giữ nguyên tại đó, không đưa
  vào repo/Git dưới bất kỳ hình thức nào.**
- Lệnh kết nối chuẩn (điền IP/cổng thật từ `DEPLOY_LOG.local.md`):
  ```powershell
  ssh -i "E:\sshkey-88735220.pem" -p <ADMIN_SSH_PORT> honeypotadmin@<VPS_IP>
  ```

### Vướng mắc đã gặp và cách xử lý (để không lặp lại lỗi)

1. **Ubuntu dùng `ssh.socket` (systemd socket activation)** — cổng trong
   `sshd_config` (`Port <ADMIN_SSH_PORT>`) bị `ssh.socket` ghi đè, vẫn nghe ở
   cổng 22 dù config đã đúng. Fix: `sudo systemctl stop ssh.socket && sudo
   systemctl disable ssh.socket && sudo systemctl restart ssh.service`.
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

## Firewall (ufw) — đã hoàn tất (Phần 3), sửa lại 2026-08-05 (xem vướng mắc #7, #8, #9)

```
Status: active
Default: deny (incoming), allow (outgoing)
<ADMIN_SSH_PORT>/tcp  ALLOW IN  Anywhere   # admin ssh (real)
2222/tcp              LIMIT IN  Anywhere   # cowrie honeypot ssh (internal, NAT target, rate-limited)
2223/tcp              LIMIT IN  Anywhere   # cowrie honeypot telnet (internal, NAT target, rate-limited)
```
`LIMIT` (không phải `ALLOW`) trên 2 cổng Cowrie — xem vướng mắc #9: 1 bot IP
tạo hơn 2300 lượt kết nối trong vài phút, đổi sang `ufw limit` để tự chặn
tạm IP nào kết nối mới ≥6 lần/30s. Allow đúng **cổng nội bộ** (2222/2223),
không phải cổng public (22/23) —
xem vướng mắc #8 để biết lý do.

## Đã xong — code repo (Phần 1)

- Repo GitHub **public**: `https://github.com/fhafqi3uq/Honeypot-Monitor`.
- 2026-08-05: commit `0aaf9c0a` (MITRE ATT&CK mapping + GO_LIVE.md +
  `deploy/` scripts + DEPLOY_LOG.md) đã push lên `origin/main`. Toàn bộ
  pytest liên quan (`test_mitre_mapping.py`, `test_parser.py`, `test_api.py`,
  `test_alerting.py` — 161 test) pass trước khi push.
- Bước kế tiếp trên VPS: `git clone https://github.com/fhafqi3uq/Honeypot-Monitor.git`
  — không cần deploy key/PAT gì cả, repo public nên clone qua HTTPS không cần
  xác thực.

## Đã xong — Cowrie + NAT + stack (Phần 4, 5, 6) — 2026-08-05

- Cowrie cài native, `pip install -e .` (thiếu bước này trong `SETUP.md` cũ,
  đã fix), nghe ở `2222` nội bộ, NAT `22 → 2222` bằng
  `deploy/expose_cowrie_port22.sh`. Verify từ máy khác: `ssh -p 22
  root@<VPS_IP>` thấy đúng banner Cowrie giả (`svr04`), không phải sshd thật.
- **Chạy NATIVE (venv), không phải Docker Compose** — xem "Vướng mắc #4" bên
  dưới để biết lý do đổi hướng giữa chừng. `bash start.sh` khởi động
  mongod + Cowrie + FastAPI (127.0.0.1:8000) + dashboard live-server
  (127.0.0.1:8080) + realtime-alert + daily-report + cleanup +
  telegram-commands + healthcheck loop, tất cả bằng nohup.
- Đã tạo tài khoản admin (`parser/create_admin.py`), đăng nhập dashboard qua
  SSH tunnel (`-L 8080:127.0.0.1:8080 -L 8000:127.0.0.1:8000`) thành công.
  `curl` trực tiếp vào `<VPS_IP>:8000`/`:8080` từ bên ngoài bị refused —
  đúng ý muốn, không lộ public.
- RAM ổn định ~49-54%, load < 0.2, swap 1GB gần như không dùng tới.

## Đã xong — tự chạy lại sau reboot (Phần 7) — 2026-08-05

- `crontab -e` (user `honeypotadmin`) có dòng:
  ```
  @reboot sleep 30 && bash /home/honeypotadmin/Honeypot-Monitor/start.sh >> /home/honeypotadmin/start_cron.log 2>&1
  ```
  `sleep 30` cho hệ thống ổn định trước khi khởi động cả stack (né lặp lại
  kiểu dội tải như vướng mắc #4). `start.sh` đã tự bao gồm vòng lặp
  `healthcheck.sh` ở cuối nên 1 dòng cron này lo được cả 2 việc (stack +
  healthcheck) — không cần thêm entry cron riêng cho `healthcheck.sh`.
  Dùng cron `@reboot` thay vì viết systemd unit riêng cho từng service, đơn
  giản hơn nhiều cho quy mô dự án này.

## Đã xong — Telnet honeypot (tăng traffic thật) — 2026-08-05

- `[telnet] enabled = true` trong `cowrie.cfg`, nghe `2223` nội bộ, NAT
  `23 → 2223` bằng `deploy/expose_cowrie_port23.sh`. Verify: `telnet
  <VPS_IP> 23` từ máy khác thấy banner `Debian GNU/Linux 12` giả, không
  phải telnetd thật. Lý do mở thêm: nhiều botnet IoT/router quét cổng 23
  tích cực hơn cả SSH — tăng lượng traffic tấn công thật thu được.
- Alert Telegram cho lệnh (`cowrie.command.input`) đã đổi từ "1 tin mỗi
  lệnh" sang "1 tin tóm tắt khi session đóng" (`alert_session_commands`,
  commit `67ac6141`) — tránh dội tin khi 1 phiên chạy nhiều lệnh recon.

## Chưa làm — bước tiếp theo

- **Quan trọng**: nâng cấp lên gói trả phí trước **07:00 08-08-2026**, không
  thì toàn bộ (kể cả code/data) bị xoá cùng máy trial.

## Vướng mắc đã gặp và cách xử lý (để không lặp lại lỗi)

4. **Docker Compose không chạy nổi trên VPS 1 CPU/1GB, kể cả sau khi giảm
   bớt xuống 8 container (bỏ Prometheus/Grafana/mongodb-exporter qua Compose
   `profiles`, xem commit `d5ce3ef3`)** — nguyên nhân gốc: file secret do
   `deploy/generate_prod_secrets.sh` tạo với quyền `600`, nhưng Compose
   standalone bind-mount thẳng file host (không normalize như Swarm), user
   trong container mongo không đọc được → `mongo` container crash-loop
   (fix: đổi sang `644`, đã vá trong script). Sau khi sửa xong, `docker
   compose up -d` (không giới hạn service) vô tình kéo cả 11 container cùng
   lúc → **1 vCPU bị nghẽn cứng, kể cả SSH mới và console web noVNC cũng
   treo không gõ được**. `sudo systemctl disable --now docker` (qua console)
   giải phóng được máy, nhưng lúc đó session đã bấm nhầm nút **Rebuild**
   (cài lại OS từ đầu) thay vì **Restart** trên panel CloudFly → mất sạch
   toàn bộ cấu hình đã làm (user, SSH hardening, firewall, NAT, code) → phải
   làm lại từ Phần 2. **Bài học: trên VPS ≤1GB RAM, bỏ qua Docker Compose
   hoàn toàn, chạy `start.sh` (native) ngay từ đầu** — nhẹ hơn nhiều, không
   có overhead build image/daemon. Cũng cẩn thận phân biệt nút **Restart**
   (khởi động lại, giữ dữ liệu) và **Rebuild** (cài lại OS, mất sạch) trên
   panel nhà cung cấp.
5. **`sudo` không chạy được sau khi tạo user bằng `adduser
   --disabled-password`** — user này không có mật khẩu nào để `sudo` xác
   thực (không phải quên, mà chưa từng có). Fix: thêm
   `honeypotadmin ALL=(ALL) NOPASSWD:ALL` vào `/etc/sudoers.d/honeypotadmin`
   (`chmod 440`, `visudo -c` để kiểm tra cú pháp trước khi tin) thay vì đặt
   thêm 1 mật khẩu phải nhớ — nhất quán với triết lý "key-only" của cả dự án.
6. **`SETUP.md` thiếu bước `pip install -e .`** khi cài Cowrie — file
   `requirements.txt` của Cowrie chỉ pin dependency, không tự cài chính
   package, nên lệnh `cowrie` (từ `pyproject.toml`'s `[project.scripts]`)
   không xuất hiện trong `cowrie-env/bin/` nếu chỉ chạy
   `pip install -r requirements.txt`. Đã vá trong `SETUP.md` (commit
   `ade3bb31`).
7. **`ufw` bị hỏng âm thầm sau khi cài lại (Rebuild) — `ufw status` báo
   `active` nhưng `sudo iptables -S` cho thấy `-P INPUT ACCEPT`** (đáng lẽ
   phải là DROP khi ufw thật sự bật). `sudo ufw allow <port>` báo lỗi mơ hồ
   `ERROR: problem running` không có chi tiết gì thêm. Nghĩa là các chain
   của ufw đã được tạo trong kernel nhưng bước đặt chính sách mặc định
   (phần "bật" thật sự) chưa bao giờ hoàn tất — VPS gần như không có tường
   lửa nào đang chặn (may mắn dashboard/API/Mongo vẫn an toàn vì tự bind
   `127.0.0.1` ở tầng ứng dụng). Fix: `sudo ufw --force reset` (backup rule
   cũ tự động) rồi chạy lại `deploy/setup_firewall.sh` từ đầu — không tìm
   ra nguyên nhân gốc chính xác gây ra trạng thái nửa-vời này, nhưng reset
   sạch rồi apply lại luôn giải quyết được.
8. **Rule ufw allow cổng PUBLIC (22/23) không có tác dụng gì — phải allow
   cổng NỘI BỘ Cowrie (2222/2223)**. iptables xử lý PREROUTING (nơi NAT
   REDIRECT 22→2222/23→2223 xảy ra) TRƯỚC bảng filter/INPUT (nơi ufw áp
   rule) — khi gói tin tới được INPUT, đích đã bị đổi thành 2222/2223 rồi,
   nên `ufw allow 22/tcp` không bao giờ khớp gói tin nào (kiểm chứng bằng
   `sudo iptables -L ufw-user-input -n -v`: 0 packet hit dù có traffic thật
   liên tục). Bug này "chạy được" trong nhiều giờ chỉ vì vướng mắc #7 (ufw
   default ACCEPT) che giấu nó - vá xong #7 thì #8 mới lộ ra (SSH/Telnet
   vào Cowrie đột nhiên timeout dù NAT + Cowrie đều chạy đúng). Đã sửa
   `deploy/setup_firewall.sh` để allow đúng cổng nội bộ mặc định.
9. **1 bot IP tạo hơn 2300 lượt kết nối trong vài phút** (loop connect →
   login → chạy lệnh → disconnect liên tục) - không có giá trị nghiên cứu
   thêm sau vài chục lượt đầu, và không muốn 1 IP chiếm hết tài nguyên trên
   máy 1GB RAM. Fix: đổi `deploy/setup_firewall.sh`'s 2 rule Cowrie từ
   `ufw allow` sang `ufw limit` (module `recent` có sẵn của ufw - REJECT
   tạm 1 IP nếu nó kết nối mới ≥6 lần/30s) thay vì tự viết rule iptables
   riêng (tránh lặp lại đúng kiểu xung đột persistence ở vướng mắc #7/#8).
   Không rate-limit cổng SSH admin - chỉ áp cho 2 cổng Cowrie.
