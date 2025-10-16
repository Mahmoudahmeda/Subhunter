#!/usr/bin/bash

echo "[+] Installing the Requirments"
pip install -r requirments.txt --break-system-package 1> /dev/null
sudo apt install chromium chromium-driver -y 1>/dev/null

echo "[+] Adding the Command"
echo alias subhunter="'python3 $(find / -name Subhunter 2>/dev/null|head -1)/Subhunter.py'" >> $HOME/.bashrc
source $HOME/.bashrc

echo "Run subhunter"