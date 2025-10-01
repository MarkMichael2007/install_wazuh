#!/bin/bash
#
# install_wazuh.sh — Automated Wazuh installer (all-in-one or roles)
#

set -euo pipefail

WAZUH_VERSION="4.x"
WAZUH_REPO_URL="https://packages.wazuh.com/${WAZUH_VERSION}/apt/"
WAZUH_KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"

ROLE="${1:-all-in-one}"   # default role = all-in-one
NODE_NAME="${2:-node01}"  # default node name = node01
MASTER_IP="${3:-}"        # only used for cluster workers

echo "[*] Starting Wazuh install (role=$ROLE, node_name=$NODE_NAME)"

# -------------------------------
# STEP 1: Fix old repo conflicts
# -------------------------------
echo "[*] Cleaning old Wazuh repo entries..."
rm -f /etc/apt/sources.list.d/wazuh.list || true
rm -f /etc/apt/sources.list.d/wazuh.repo || true

# -------------------------------
# STEP 2: Install prereqs & add repo
# -------------------------------
echo "[*] Installing prerequisites..."
apt-get update -y
apt-get install -y gnupg apt-transport-https curl tar

echo "[*] Adding Wazuh GPG key..."
curl -s "$WAZUH_KEY_URL" | gpg --dearmor > /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "[*] Adding Wazuh repository..."
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] $WAZUH_REPO_URL stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update -y

# -------------------------------
# STEP 3: All-in-one install
# -------------------------------
if [[ "$ROLE" == "all-in-one" ]]; then
    echo "[*] Downloading official Wazuh installer..."
    rm -f wazuh-install.sh
    curl -L -o wazuh-install.sh https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh

    echo "[*] Checking installer header..."
    head -n 1 wazuh-install.sh | grep -q "#!" || { echo "[!] ERROR: installer corrupted"; exit 1; }

    chmod +x wazuh-install.sh
    echo "[*] Running Wazuh all-in-one installer..."
    ./wazuh-install.sh --all-in-one "$NODE_NAME"

    echo "[✅] All-in-one Wazuh installation finished!"
    exit 0
fi

# -------------------------------
# STEP 4: Role-based installs
# -------------------------------
if [[ "$ROLE" == "server" ]]; then
    apt-get install -y wazuh-manager filebeat
    echo "[✅] Installed Wazuh server + Filebeat. Configure certs + filebeat.yml manually."
    exit 0
fi

if [[ "$ROLE" == "dashboard" ]]; then
    apt-get install -y wazuh-dashboard
    echo "[✅] Installed Wazuh dashboard. Configure /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml."
    exit 0
fi

if [[ "$ROLE" == "indexer" ]]; then
    apt-get install -y wazuh-indexer
    echo "[✅] Installed Wazuh indexer. Configure cluster.yml manually."
    exit 0
fi

if [[ "$ROLE" == "cluster-server" ]]; then
    if [[ -z "$MASTER_IP" ]]; then
        echo "Usage: $0 cluster-server <node_name> <master_ip>"
        exit 1
    fi
    apt-get install -y wazuh-manager filebeat
    echo "[✅] Installed cluster worker node ($NODE_NAME). Configure ossec.conf with master IP: $MASTER_IP."
    exit 0
fi

echo "[!] Unknown role: $ROLE"
exit 1
