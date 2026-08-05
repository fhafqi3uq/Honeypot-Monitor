# Checklist go-live — đưa Cowrie lên VPS công khai

Tài liệu này trả lời câu hỏi: "làm sao đưa honeypot từ local lên internet để
nhận traffic tấn công thật, mà không biến VPS thành lỗ hổng bảo mật?"

**Nguyên tắc cốt lõi — chỉ 1 thứ được public:** cổng SSH giả của Cowrie.
Mọi thứ khác (dashboard, `/api/*`, MongoDB, Prometheus, Grafana) tiếp tục
bind `127.0.0.1` **đúng như hiện tại** (đã kiểm tra trong `docker-compose.yml`
— không cần sửa gì ở đó) và chỉ được xem qua SSH tunnel. Không có bước nào
trong checklist này thay đổi nguyên tắc đó.

---

## 0. Chọn VPS

Tình hình tính đến 08/2026 (kiểm tra trực tiếp, không suy đoán):

- **DigitalOcean student credit (GitHub Student Pack)**: đã bị khai tử
  1/8/2026 — không còn $200 free nữa, kể cả credit cấp trước đó cũng đã hết
  hạn. Đừng đi theo hướng này.
- **Azure for Students** (vẫn còn trong GitHub Student Pack, cần xác minh
  email trường): $100 credit, không cần thẻ tín dụng để verify. Đủ chạy
  VPS nhỏ ~1 năm nếu chọn size hợp lý.
- **Oracle Cloud Always Free**: tồn tại vĩnh viễn (không hết hạn) nhưng từ
  6/2026 đã giảm giới hạn ARM instance xuống còn 2 OCPU/12GB, và có báo cáo
  người dùng bị **khoá tài khoản không báo trước** khi hệ thống phát hiện
  workload "bất thường" — một honeypot công khai nhận hàng trăm connection
  scan/giờ đúng kiểu traffic dễ bị flag nhầm là abuse. Có thể dùng để **thử
  nghiệm** nhưng đừng coi là hạ tầng ổn định cho báo cáo/đồ án cuối kỳ.
- **RackNerd**: rẻ nhất cho "vài chục nghìn/tháng" bạn hỏi — khuyến mãi
  thường niên xuống ~$15-20/năm (~35-45k VNĐ/tháng) cho 1GB RAM. Trả theo
  năm.
- **Vultr**: ~$6/tháng, tính theo giờ (destroy bất cứ lúc nào không mất phí
  đã trả trước) — hợp để thử nghiệm ban đầu trước khi cam kết trả theo năm.

**Khuyến nghị**: Vultr trả theo giờ để dựng thử/kiểm tra checklist này lần
đầu (dễ huỷ, không tiếc tiền nếu làm sai), sau khi ổn thì chuyển sang
RackNerd trả năm để tiết kiệm. Oracle Free Tier chỉ nên là phương án dự
phòng/thử nghiệm, không phải phương án chính.

**Cấu hình tối thiểu**: Cowrie + MongoDB + FastAPI + Prometheus + Grafana
chạy cùng lúc — khuyến nghị **≥ 2GB RAM**. Nếu VPS chỉ có 1GB, cân nhắc
không chạy Prometheus/Grafana trên chính VPS honeypot (chỉ chạy
mongo + parser + notifier + dashboard), xem log qua `docker compose logs`
thay vì Grafana.

**Trước khi tạo VPS**: đọc Acceptable Use Policy của nhà cung cấp — honeypot
chỉ *nhận* traffic không mời (passive), không tấn công/relay ai, nên hầu hết
provider chấp nhận. Nhưng bạn **sẽ** nhận được abuse-report email tự động từ
các bên quét mạng (Shodan, Censys, GreyNoise, ISP của kẻ tấn công...) — đây
là chuyện bình thường với honeypot công khai, không phải dấu hiệu bạn làm
sai, không cần phản hồi trừ khi provider yêu cầu.

---

## 1. Kiến trúc mạng mục tiêu

```
Internet ──▶ VPS:22  (Cowrie giả lập SSH — CÔNG KHAI, đây là mục đích)
Internet ──▶ VPS:23  (Cowrie giả lập Telnet — CÔNG KHAI, cùng mục đích)
Internet ──▶ VPS:<ADMIN_SSH_PORT>  (sshd thật — key-only, đổi khỏi 22)
Internet ──X  mọi cổng khác bị ufw chặn

Bạn ──▶ SSH tunnel (-L) ──▶ 127.0.0.1:8080/8000/3000/9090 trên VPS
        (dashboard/API/Grafana/Prometheus — KHÔNG public)
```

Cowrie trong repo này (`honeypot/cowrie.cfg`) lắng nghe SSH ở
`tcp:2222:interface=0.0.0.0` và Telnet ở `tcp:2223:interface=0.0.0.0`
(`[telnet] enabled = true`) — không chạy bằng root nên không tự bind được
cổng 22/23 (privileged port). Cách chuẩn: NAT port 22 → 2222 và 23 → 2223
bằng iptables (xem bước 4), **không** đổi Cowrie sang chạy root. Mở cả
Telnet vì nhiều botnet IoT/router quét cổng 23 tích cực hơn cả SSH — tăng
đáng kể lượng traffic tấn công thật thu được so với chỉ mở SSH.

---

## 2. Hardening SSH thật (làm THỦ CÔNG, không script — sai một bước là tự
khoá mình ngoài VPS)

Thứ tự bắt buộc — **không đóng session SSH hiện tại cho tới khi xác nhận
xong bước cuối**:

1. Tạo user thường (không dùng root cho việc hàng ngày), thêm SSH public
   key vào `~/.ssh/authorized_keys` của user đó.
2. Mở **session SSH thứ hai** (giữ session đầu còn sống), login bằng user
   mới + key, xác nhận vào được và `sudo` chạy được.
3. Sửa `/etc/ssh/sshd_config`:
   ```
   Port <ADMIN_SSH_PORT>      # ví dụ 2200 — bất kỳ số nào KHÁC 22 và KHÁC 2222
   PasswordAuthentication no
   PermitRootLogin no
   ```
4. `sudo systemctl restart sshd`
5. Mở **session SSH thứ ba** tới `<ADMIN_SSH_PORT>` mới — xác nhận vào
   được **trước khi** đóng 2 session cũ. Nếu session thứ ba fail, sửa lại
   `sshd_config` và restart lại từ session đầu (vẫn đang mở).

Chỉ sau khi bước 5 thành công mới chuyển sang phần 3.

---

## 3. Firewall — `deploy/setup_firewall.sh`

```bash
sudo bash deploy/setup_firewall.sh <ADMIN_SSH_PORT> [COWRIE_SSH_PORT=22] [COWRIE_TELNET_PORT=23]
```

Script bắt buộc bạn truyền `ADMIN_SSH_PORT` tường minh (không có default) để
tránh trường hợp quên đổi cổng SSH thật rồi tự khoá mình ngoài. Xem chi tiết
trong script — nó allow 3 cổng đó trước (SSH admin, Cowrie SSH, Cowrie
Telnet), deny-by-default sau, rồi mới bật ufw.

---

## 4. NAT cổng 22 + 23 vào Cowrie — `deploy/expose_cowrie_port22.sh` + `deploy/expose_cowrie_port23.sh`

```bash
sudo bash deploy/expose_cowrie_port22.sh [COWRIE_INTERNAL_PORT=2222]
sudo bash deploy/expose_cowrie_port23.sh [COWRIE_INTERNAL_PORT=2223]
```

Redirect `22 → 2222` (SSH) và `23 → 2223` (Telnet) bằng iptables PREROUTING,
persist qua reboot. Cowrie's `[telnet] enabled = true` trong `cowrie.cfg` -
mở thêm Telnet vì nhiều botnet IoT/router quét cổng 23 nhiều hơn cả SSH,
tăng lượng traffic tấn công thật thu được. Script `expose_cowrie_port22.sh`
tự kiểm tra không có sshd thật nào đang bind port 22 trước khi áp rule
(tránh xung đột) — nếu có, dừng lại và nhắc bạn hoàn thành phần 2 trước;
`expose_cowrie_port23.sh` kiểm tra tương tự cho port 23 (thường trống sẵn,
Ubuntu không cài telnetd mặc định).

---

## 5. Deploy stack

Theo đúng `SETUP.md` (Docker Compose workflow), với 2 khác biệt so với dev
local:

1. **Sinh secrets thật trên VPS**, không copy secrets dev từ máy local:
   ```bash
   bash deploy/generate_prod_secrets.sh
   ```
2. Cowrie vẫn chạy native (không đổi) — `cd honeypot/cowrie-src && ... &&
   cowrie-env/bin/cowrie start` — rồi `docker compose up -d --build` như
   SETUP.md đã ghi. Mặc định lệnh này **không** chạy Prometheus/Grafana/
   mongodb-exporter (`profiles: ["observability"]` trong
   `docker-compose.yml`) — đúng ý "bỏ Prometheus + Grafana" ở mục RAM thấp
   phía trên, giờ là hành vi mặc định chứ không cần tự nhớ bỏ bớt service.

---

## 6. Xác minh sau khi lên

Từ **một máy khác** (không phải VPS):

```bash
# Cowrie phải trả lời ở 22 VÀ 23, banner phải là "svr04" (hostname giả
# trong cowrie.cfg), KHÔNG phải banner sshd/telnetd thật của Ubuntu/Debian:
ssh -p 22 root@<vps-ip>          # kỳ vọng: nhận prompt/banner Cowrie, không phải lỗi permission thật
telnet <vps-ip> 23                # kỳ vọng: banner login giả, không phải telnetd thật (thường không cài sẵn)

# Dashboard/API KHÔNG được lộ ra ngoài:
curl -m 3 http://<vps-ip>:8000/  # kỳ vọng: timeout hoặc connection refused
curl -m 3 http://<vps-ip>:8080/  # kỳ vọng: timeout hoặc connection refused

# nmap nhanh (nếu có) — public chỉ nên thấy 22 + 23 (Cowrie) + ADMIN_SSH_PORT:
nmap -Pn <vps-ip>
```

Truy cập dashboard thật sự (từ máy bạn):

```bash
ssh -p <ADMIN_SSH_PORT> -L 8080:127.0.0.1:8080 -L 8000:127.0.0.1:8000 \
    -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 user@<vps-ip>
# rồi mở http://localhost:8080 trên máy bạn như bình thường
```

---

## 7. Giám sát & bảo trì liên tục

- Đặt `healthcheck.sh` chạy định kỳ qua cron (`*/1 * * * *` hoặc tương tự) —
  hiện tại nó chỉ chạy thủ công/qua `start.sh`.
- Honeypot công khai nhận traffic nhiều hơn hẳn local — theo dõi dung lượng
  đĩa (`df -h`) trong tuần đầu, `cleanup.py` đã tự xoá dữ liệu >30 ngày
  nhưng log Cowrie thô có thể tích luỹ nhanh hơn dự kiến ban đầu.
- Backup MongoDB định kỳ (`mongodump`) nếu dữ liệu thu được có giá trị cho
  báo cáo — không có cơ chế backup tự động nào trong repo hiện tại.

---

## 8. Kill-switch (khi cần tắt nhanh)

```bash
sudo ufw deny 22/tcp                    # ngắt traffic SSH vào Cowrie ngay lập tức
sudo ufw deny 23/tcp                    # ngắt traffic Telnet vào Cowrie ngay lập tức
# hoặc
cd honeypot/cowrie-src && cowrie-env/bin/cowrie stop
# hoặc dừng toàn bộ stack Docker:
docker compose down                     # KHÔNG thêm -v (xoá sạch dữ liệu Mongo)
```

---

## 9. Giới hạn đạo đức/kỹ thuật — đừng đổi

- Cowrie là honeypot **medium-interaction giả lập** — không cho attacker
  thực thi lệnh thật trên hệ thống thật. Đừng bật `[shell]`/cấu hình nào cho
  phép exec thật hoặc dùng máy này làm bàn đạp/relay sang hệ thống khác —
  làm vậy biến honeypot thành công cụ tấn công thật, vượt ra ngoài mục đích
  nghiên cứu/học tập.
- Nếu viết báo cáo/blog từ dữ liệu thu được: tổng hợp thống kê (top IP,
  top password, số lượt/ngày...) thay vì công khai toàn bộ log thô — log thô
  vẫn chứa IP thật của người/máy đã kết nối.
