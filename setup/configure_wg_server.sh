#!/bin/bash
# ------------------------------
# WireGuard Server Configuration
# ------------------------------

set -e

WG_DIR="/etc/wireguard"
WG_CONF="$WG_DIR/wg0.conf"
SERVER_PRIV="$WG_DIR/server_private.key"
SERVER_PUB="$WG_DIR/server_public.key"
SERVER_PORT=51820
VPN_SUBNET="10.8.0.0/24"
NET_IFACE="enp0s8"


echo "[+] Creating WireGuard config directory (if not exists)..."
sudo mkdir -p "$WG_DIR"
sudo chmod 700 "$WG_DIR"

echo "[+] Generating server keys..."
if [ ! -f "$SERVER_PRIV" ]; then
    sudo wg genkey | sudo tee "$SERVER_PRIV" > /dev/null
    sudo cat "$SERVER_PRIV" | sudo wg pubkey | sudo tee "$SERVER_PUB" > /dev/null
else
    echo "[-] Keys already exist, skipping..."
fi

echo "[+] Building wg0.conf..."
sudo bash -c "cat > $WG_CONF" <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = $SERVER_PORT
PrivateKey = $(sudo cat $SERVER_PRIV)
SaveConfig = true

# (Clients will be added below as [Peer] sections) 
EOF

echo "[+] Setting correct permissions..."
sudo chmod 600 "$WG_CONF"

echo "[+] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf > /dev/null
grep -qxF 'net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf || echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf > /dev/null
 
echo "[+] Starting WireGuard service..."
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

echo "[+] WireGuard Server setup complete."
echo "--------------------------------------"
echo "Server public key (for clients):"
sudo cat "$SERVER_PUB"
echo "--------------------------------------"
sudo wg show
