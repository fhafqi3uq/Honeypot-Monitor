#!/bin/bash
# Bật honeypot-vm (Azure) + khởi động lại Cowrie + đảm bảo Docker Compose
# đang chạy - dùng hàng ngày sau khi Auto-shutdown đã tắt VM đêm trước.
#
# Chạy từ MÁY LOCAL (không phải trong VM) - cần Azure CLI đã `az login`.
#
# Dùng: bash deploy/start_honeypot_vm.sh
set -euo pipefail

RESOURCE_GROUP="SOC"
VM_NAME="honeypot-vm"
VM_IP="23.100.95.135"
SSH_KEY="$HOME/.ssh/honeypot-vm_key.pem"
SSH_PORT="2200"
SSH_USER="azureuser"
SSH_OPTS=(-i "$SSH_KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5)

echo "==> Bật VM $VM_NAME (resource group $RESOURCE_GROUP)"
az vm start --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --no-wait

echo "==> Đợi VM sẵn sàng nhận SSH (tối đa 5 phút)"
for i in $(seq 1 60); do
    if ssh "${SSH_OPTS[@]}" "$SSH_USER@$VM_IP" "echo ok" >/dev/null 2>&1; then
        echo "    SSH sẵn sàng."
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "LỖI: VM không phản hồi SSH sau 5 phút. Kiểm tra thủ công qua Azure Portal." >&2
        exit 1
    fi
    sleep 5
done

echo "==> Khởi động Cowrie (idempotent - bỏ qua nếu đã chạy)"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$VM_IP" '
    cd ~/Honeypot-Monitor/honeypot/cowrie-src
    if cowrie-env/bin/cowrie status 2>/dev/null | grep -q "is running"; then
        echo "    Cowrie đã chạy sẵn."
    else
        source cowrie-env/bin/activate
        cowrie-env/bin/cowrie start
        sleep 2
        cowrie-env/bin/cowrie status
    fi
'

echo "==> Đảm bảo Docker Compose đang chạy"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$VM_IP" '
    cd ~/Honeypot-Monitor
    sudo docker compose up -d
    sudo docker compose ps --format "table {{.Name}}\t{{.Status}}"
'

# Azure "stop" (dealloc qua đêm) reset network stack của VM - mọi rule NAT
# thêm bằng iptables -A thì mất, TRỪ KHI iptables-persistent đã lưu. Kiểm
# tra + thêm lại (idempotent, dùng -C để không tạo rule trùng) mỗi lần bật
# VM, thay vì giả định rule cũ vẫn còn - đây chính là lý do web honeypot
# (cổng 80) từng "mất tích" sau một lần bật lại VM trong khi Cowrie (cổng
# 22/23) vẫn ổn, vì bug này chưa được vá.
echo "==> Kiểm tra/khôi phục NAT rules (22->2222, 23->2223, 80->8899)"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$VM_IP" '
    add_nat() {
        local dport="$1" toport="$2"
        if ! sudo iptables -t nat -C PREROUTING -p tcp --dport "$dport" -j REDIRECT --to-port "$toport" 2>/dev/null; then
            echo "    Thiếu rule $dport->$toport, đang thêm lại..."
            sudo iptables -t nat -A PREROUTING -p tcp --dport "$dport" -j REDIRECT --to-port "$toport"
        else
            echo "    Rule $dport->$toport đã có sẵn."
        fi
    }
    add_nat 22 2222
    add_nat 23 2223
    add_nat 80 8899
'

cat <<EOF

==> Xong! Honeypot đang chạy tại $VM_IP.
    Dashboard/API/Grafana: mở tunnel riêng khi cần xem (dashboard chạy qua
    container nginx cổng 8080, KHÔNG phải 8081 - đó là live-server của
    workflow native cũ, không còn chạy trên VM này nữa):
      ssh -i $SSH_KEY -p $SSH_PORT -L 8080:localhost:8080 -L 8000:localhost:8000 -L 3000:localhost:3000 $SSH_USER@$VM_IP
EOF
