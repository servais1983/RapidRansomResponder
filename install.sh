#!/bin/bash
echo "[*] Installation de R3..."

sudo apt update
sudo apt install -y python3 python3-pip

echo "[✓] R3 installé. Exemple de commande :"
echo "python3 r3.py --epicenter 192.168.1.45"
