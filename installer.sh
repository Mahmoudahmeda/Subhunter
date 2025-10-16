#!/usr/bin/bash

echo "[+] Installing the Requirments"
pip install -r requirments.txt 1> /dev/null

echo "[+] Adding the Command"
alias subhunter="python3 Subhunter.py"
source $HOME/.bashrc

echo "Run subhunter"