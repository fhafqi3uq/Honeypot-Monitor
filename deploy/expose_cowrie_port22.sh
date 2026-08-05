#!/bin/bash
# NAT public port 22 -> cổng nội bộ Cowrie (mặc định 2222, khớp
# honeypot/cowrie.cfg's listen_endpoints = tcp:2222:interface=0.0.0.0).
# Cowrie chạy user thường nên không tự bind được cổng 22 (privileged port) -
# đây là cách chuẩn để nó "trông giống" SSH thật trên cổng mặc định mà
# scanner/attacker sẽ thử trước tiên, mà không cần chạy Cowrie bằng root.
#
# Dùng: sudo bash deploy/expose_cowrie_port22.sh [COWRIE_INTERNAL_PORT=2222]
set -euo pipefail

COWRIE_INTERNAL_PORT="${1:-2222}"
PUBLIC_PORT=22

if ss -tlnp 2>/dev/null | grep -q ":${PUBLIC_PORT} .*sshd"; then
    echo "LỖI: sshd thật vẫn đang bind cổng $PUBLIC_PORT." >&2
    echo "Hoàn thành GO_LIVE.md phần 2 (đổi sshd sang cổng khác) trước." >&2
    exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "LỖI: iptables chưa được cài." >&2
    exit 1
fi

echo "==> Thêm rule NAT: public $PUBLIC_PORT -> 127.0.0.1:$COWRIE_INTERNAL_PORT"
iptables -t nat -A PREROUTING -p tcp --dport "$PUBLIC_PORT" -j REDIRECT --to-port "$COWRIE_INTERNAL_PORT"

echo "==> Persist rule qua reboot"
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
elif dpkg -l iptables-persistent >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
else
    cat <<EOF

CHƯA PERSIST: cài iptables-persistent để rule này sống qua reboot:
  sudo apt-get install -y iptables-persistent
  sudo netfilter-persistent save

Nếu không cài, rule sẽ mất sau khi VPS restart và cần chạy lại script này.
EOF
fi

cat <<EOF

Đã redirect: internet:$PUBLIC_PORT -> 127.0.0.1:$COWRIE_INTERNAL_PORT (Cowrie)

Xác minh (từ máy khác, sau khi Cowrie đã start):
  ssh -p 22 root@<vps-ip>    # kỳ vọng thấy banner Cowrie giả (hostname "svr04"), không phải sshd thật
EOF
