#!/bin/bash

#Install WireGuard VPN

set -e

echo "[+] Updating system...."
sudo apt update && sudo apt upgrade -y

echo "[+] Installing WireGuard...."
sudo apt install -y wireguard wireguard-tools resolvconf

echo "[+]Enabling IP forwarding...."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf

echo "[+] Done! WireGuard installed and forwarding enabled."


