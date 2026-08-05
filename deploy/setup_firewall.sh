#!/bin/bash
# Cấu hình ufw cho VPS public: chỉ mở cổng SSH thật (đã đổi khỏi 22, xem
# GO_LIVE.md phần 2) và 2 cổng Cowrie - SSH giả và Telnet giả (mặc định
# 2222/2223, honeypot.cfg's [ssh]/[telnet] listen_endpoints - nhiều botnet
# IoT/router quét Telnet nhiều hơn SSH, mở thêm cổng này giúp thu được
# nhiều traffic hơn).
#
# QUAN TRỌNG: allow đúng CỔNG NỘI BỘ Cowrie (2222/2223), KHÔNG PHẢI cổng
# public (22/23). iptables xử lý PREROUTING (nơi expose_cowrie_port22.sh/
# port23.sh làm REDIRECT 22->2222, 23->2223) TRƯỚC bảng filter/INPUT (nơi
# ufw áp rule) - nghĩa là khi gói tin tới được INPUT, đích của nó ĐÃ bị đổi
# thành 2222/2223 rồi, nên rule "allow 22/tcp" không bao giờ khớp được gì
# cả (0 packet, đã kiểm chứng thật trên VPS). Bug này từng "chạy được" chỉ
# vì lúc đó ufw bị hỏng (default policy ACCEPT thay vì DROP) nên không
# thực sự chặn gì - vá xong bug ufw thì bug allow-sai-cổng này mới lộ ra.
#
# Dùng: sudo bash deploy/setup_firewall.sh <ADMIN_SSH_PORT> [COWRIE_SSH_INTERNAL_PORT=2222] [COWRIE_TELNET_INTERNAL_PORT=2223]
set -euo pipefail

ADMIN_SSH_PORT="${1:?Thiếu ADMIN_SSH_PORT - xem GO_LIVE.md phần 2 (cổng SSH thật, PHẢI khác 22)}"
COWRIE_SSH_INTERNAL_PORT="${2:-2222}"
COWRIE_TELNET_INTERNAL_PORT="${3:-2223}"

if [ "$ADMIN_SSH_PORT" = "$COWRIE_SSH_INTERNAL_PORT" ] || [ "$ADMIN_SSH_PORT" = "$COWRIE_TELNET_INTERNAL_PORT" ]; then
    echo "LỖI: ADMIN_SSH_PORT không được trùng cổng nội bộ Cowrie ($COWRIE_SSH_INTERNAL_PORT/$COWRIE_TELNET_INTERNAL_PORT)." >&2
    echo "SSH thật và Cowrie phải là các cổng khác nhau." >&2
    exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
    echo "LỖI: ufw chưa được cài. Chạy: sudo apt-get install -y ufw" >&2
    exit 1
fi

echo "==> Allow cổng SSH thật: $ADMIN_SSH_PORT/tcp"
ufw allow "${ADMIN_SSH_PORT}/tcp" comment 'admin ssh (real)'

echo "==> Rate-limit cổng Cowrie SSH nội bộ (đích sau NAT redirect từ 22): $COWRIE_SSH_INTERNAL_PORT/tcp"
# 'ufw limit' (không phải 'allow') - dùng module `recent` có sẵn của ufw,
# tự động chặn tạm 1 IP nếu nó kết nối mới >= 6 lần trong 30 giây. Gặp thật
# 1 bot lặp connect/login/disconnect >2000 lần/vài phút - "allow" thường
# không có gì cản, "limit" chặn bớt mà không cần cài thêm gói/tự viết rule
# iptables riêng (tránh lặp lại xung đột persistence với ufw như trước).
ufw limit "${COWRIE_SSH_INTERNAL_PORT}/tcp" comment 'cowrie honeypot ssh (internal, NAT target, rate-limited)'

echo "==> Rate-limit cổng Cowrie Telnet nội bộ (đích sau NAT redirect từ 23): $COWRIE_TELNET_INTERNAL_PORT/tcp"
ufw limit "${COWRIE_TELNET_INTERNAL_PORT}/tcp" comment 'cowrie honeypot telnet (internal, NAT target, rate-limited)'

echo "==> Default deny incoming, allow outgoing"
ufw default deny incoming
ufw default allow outgoing

echo "==> Bật ufw"
ufw --force enable

ufw status verbose

cat <<EOF

Đã bật ufw với:
  - $ADMIN_SSH_PORT/tcp mở (SSH thật, không giới hạn)
  - $COWRIE_SSH_INTERNAL_PORT/tcp mở, rate-limited (Cowrie SSH - đích sau NAT từ cổng 22 public)
  - $COWRIE_TELNET_INTERNAL_PORT/tcp mở, rate-limited (Cowrie Telnet - đích sau NAT từ cổng 23 public)
  - Mọi cổng khác bị chặn từ bên ngoài

Rate-limit (ufw limit) = 1 IP kết nối mới >= 6 lần trong 30 giây sẽ bị REJECT
tạm thời cho tới khi giảm tần suất. Đủ để chặn bot spam hàng nghìn lượt/vài
phút mà vẫn giữ được kha khá mẫu traffic từ mỗi IP trước khi bị chặn.

Chạy script này TRƯỚC deploy/expose_cowrie_port22.sh + expose_cowrie_port23.sh
hoặc sau đều được - thứ tự không quan trọng, chỉ cần cả 2 cùng có mặt để
traffic public 22/23 thật sự chạm được tới Cowrie.

QUAN TRỌNG: đừng đóng session SSH hiện tại cho tới khi bạn đã mở một
session SSH MỚI tới cổng $ADMIN_SSH_PORT và xác nhận vào được thành công.
EOF
