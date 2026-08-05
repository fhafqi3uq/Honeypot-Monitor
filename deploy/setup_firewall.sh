#!/bin/bash
# Cấu hình ufw cho VPS public: chỉ mở cổng SSH thật (đã đổi khỏi 22, xem
# GO_LIVE.md phần 2) và 2 cổng Cowrie - SSH giả (mặc định 22) và Telnet giả
# (mặc định 23, honeypot.cfg's [telnet] enabled=true - nhiều botnet IoT/router
# quét Telnet nhiều hơn SSH, mở thêm cổng này giúp thu được nhiều traffic
# hơn). Mọi cổng khác (dashboard 8080, API 8000, Mongo 27017, Prometheus
# 9090, Grafana 3000) đã tự bind 127.0.0.1 trong docker-compose.yml nên
# không lộ ra ngoài dù không có rule ufw riêng - script này chỉ deny-by-
# default để phòng thủ theo chiều sâu (defense in depth), không phải điều
# kiện cần.
#
# Dùng: sudo bash deploy/setup_firewall.sh <ADMIN_SSH_PORT> [COWRIE_SSH_PORT=22] [COWRIE_TELNET_PORT=23]
set -euo pipefail

ADMIN_SSH_PORT="${1:?Thiếu ADMIN_SSH_PORT - xem GO_LIVE.md phần 2 (cổng SSH thật, PHẢI khác 22)}"
COWRIE_PORT="${2:-22}"
COWRIE_TELNET_PORT="${3:-23}"

if [ "$ADMIN_SSH_PORT" = "$COWRIE_PORT" ] || [ "$ADMIN_SSH_PORT" = "$COWRIE_TELNET_PORT" ]; then
    echo "LỖI: ADMIN_SSH_PORT không được trùng cổng Cowrie ($COWRIE_PORT/$COWRIE_TELNET_PORT)." >&2
    echo "SSH thật và Cowrie phải là các cổng khác nhau." >&2
    exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
    echo "LỖI: ufw chưa được cài. Chạy: sudo apt-get install -y ufw" >&2
    exit 1
fi

echo "==> Allow cổng SSH thật: $ADMIN_SSH_PORT/tcp"
ufw allow "${ADMIN_SSH_PORT}/tcp" comment 'admin ssh (real)'

echo "==> Allow cổng Cowrie SSH giả (honeypot công khai): $COWRIE_PORT/tcp"
ufw allow "${COWRIE_PORT}/tcp" comment 'cowrie honeypot ssh'

echo "==> Allow cổng Cowrie Telnet giả (honeypot công khai): $COWRIE_TELNET_PORT/tcp"
ufw allow "${COWRIE_TELNET_PORT}/tcp" comment 'cowrie honeypot telnet'

echo "==> Default deny incoming, allow outgoing"
ufw default deny incoming
ufw default allow outgoing

echo "==> Bật ufw"
ufw --force enable

ufw status verbose

cat <<EOF

Đã bật ufw với:
  - $ADMIN_SSH_PORT/tcp mở (SSH thật)
  - $COWRIE_PORT/tcp mở (Cowrie honeypot SSH)
  - $COWRIE_TELNET_PORT/tcp mở (Cowrie honeypot Telnet)
  - Mọi cổng khác bị chặn từ bên ngoài

QUAN TRỌNG: đừng đóng session SSH hiện tại cho tới khi bạn đã mở một
session SSH MỚI tới cổng $ADMIN_SSH_PORT và xác nhận vào được thành công.
EOF
