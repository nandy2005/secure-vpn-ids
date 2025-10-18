#!/bin/bash
#-------------------------------
#WireGuaerd Client Configuration
#-------------------------------

set -e

SERVER_PUBLIC_KEY="1Q2OaYHHukseRhsiP83X7xMXafL2km3HpW+xYKjCqCg="
SERVER_ENDPOINT="192.168.56.106:51820"
CLIENT_IP="10.8.0.2/24"
CLIENT_NAME="wg-client"
DNS_SERVER="1.1.1.1"

CLIENT_DIR="/etc/wireguard"
PRIVATE_KEY_FILE="$CLIENT_DIR/client_private.key"
PUBLIC_KEY_FILE="$CLIENT_DIR/client_public.key"
CONF_FILE="$CLIENT_DIR/${CLIENT_NAME}.conf"

sudo mkdir -p "$CLIENT_DIR"
sudo chmod 700 "$CLIENT_DIR"

#Generate client keys
if [ ! -f "$PRIVATE_KEY_FILE" ]; then
	sudo wg genkey | sudo tee "$PRIVATE_KEY_FILE" > /dev/null
	cat "$PRIVATE_KEY_FILE" |sudo  wg pubkey | sudo tee "$PUBLIC_KEY_FILE" >  /dev/null
	echo "[+] Client keys generated."
else
	echo "[-] Client keys already exist, skipping."
fi

CLIENT_PRIVATE_KEY=$(sudo cat "$PRIVATE_KEY_FILE")

#Create client config
sudo bash -c "cat > $CONF_FILE <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = $DNS_SERVER

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF"

sudo chmod 600 "$CONF_FILE"
echo "[+] Client config created: $CONF_FILE"

#Bring up the VPN
sudo wg-quick down "$CLIENT_NAME" 2>/dev/null || true
sudo wg-quick up "$CLIENT_NAME"

#Verify connection
echo "[+] VPN is up.Status:"
sudo wg show

#SERVER_VPN_IP ="10.8.0.1"
#echo "[+] Testing connectivity to server VPN IP ($SERVER_VPN_IP).."
#ping -c 4 "$SERVER_VPN_IP"

