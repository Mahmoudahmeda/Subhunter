#!/usr/bin/bash

echo "[+] Installing the Requirments"
pip install -r requirments.txt --break-system-package 1> /dev/null

echo "[+] Adding the Command"
echo alias subhunter="python3 Subhunter.py" >> $HOME/.bashrc
source $HOME/.bashrc

echo "Run subhunter"