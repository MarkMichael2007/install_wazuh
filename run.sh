#!/bin/bash
#
# wz-install.sh — Install Wazuh server + indexer + dashboard (or parts) in a mostly automated way
#
# Usage:
#   ./wz-install.sh <role> <node_name> <master_ip> [other nodes...]
# Roles:
#   all-in-one      → install indexer + server + dashboard on this node
#   server           → install just Wazuh server/manager + filebeat
#   dashboard        → install just the dashboard
#   indexer          → install just the indexer
#   cluster-server   → install server in a cluster (worker)  
#
# Examples:
#   ./wz-install.sh all-in-one node01
#   ./wz-install.sh server node01
#   ./wz-install.sh dashboard dash01
#   ./wz-install.sh indexer idx01
#   ./wz-install.sh cluster-server node02 <master-ip>
#
set -e
set -o pipefail

# === CONFIGURATION YOU MUST FILL / ADJUST ===
WAZUH_VERSION="4.x"  # or specify exact version
WAZUH_REPO_URL="https://packages.wazuh.com/${WAZUH_VERSION}/apt/"
WAZUH_KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
CLUSTER_NAME="wazuh"
MASTER_NODE_NAME="node01"  # for cluster-server or multi-node
# If in cluster mode, supply this script with MASTER_IP
# For all-in-one or single node, MASTER_IP = localhost or same node

# === ARGUMENTS ===
ROLE="$1"        # all-in-one / server / dashboard / indexer / cluster-server
NODE_NAME="$2"
MASTER_IP="$3"

if [[ -z "$ROLE" || -z "$NODE_NAME" ]]; then
  echo "Usage: $0 <role> <node_name> [master_ip]" >&2
  exit 1
fi

echo "[*] Starting Wazuh install script (role=$ROLE, node_name=$NODE_NAME)"

## -- Step 1: Install prerequisites, add Wazuh repo

echo "[*] Installing prerequisites & adding Wazuh repository..."
apt-get update
DEPS="gnupg apt-transport-https curl tar"
apt-get install -y $DEPS

# Add GPG key
curl -s "$WAZUH_KEY_URL" | gpg --dearmor > /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg

# Add repo
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] $WAZUH_REPO_URL stable main" | tee /etc/apt/sources.list.d/wazuh.list

apt-get update

## -- Step 2: If doing all-in-one, use the Wazuh installation assistant

if [[ "$ROLE" == "all-in-one" ]]; then
  echo "[*] Installing all-in-one (indexer + server + dashboard) via Wazuh install assistant..."
  curl -sO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh
  chmod +x wazuh-install.sh
  # -a = all central components, node name must match
  bash ./wazuh-install.sh --all-in-one "$NODE_NAME"
  echo "[*] All-in-one installation done. Review output and proceed."
  exit 0
fi

## -- Step 3: For separate component installs

# 3A. If installing indexer
if [[ "$ROLE" == "indexer" ]]; then
  echo "[*] Installing Wazuh indexer..."
  apt-get install -y wazuh-indexer
  # (You may need to initialize cluster, set config etc — manual steps)
  systemctl daemon-reload
  systemctl enable wazuh-indexer
  systemctl start wazuh-indexer
  echo "[*] Indexer installed."
  exit 0
fi

# 3B. If installing server (manager + filebeat)
if [[ "$ROLE" == "server" || "$ROLE" == "cluster-server" ]]; then
  echo "[*] Installing Wazuh manager + filebeat..."

  apt-get install -y wazuh-manager filebeat

  # Configure certificate extraction if cluster / secure
  echo "[*] Expecting wazuh-certificates.tar in current directory"
  if [[ ! -f ./wazuh-certificates.tar ]]; then
    echo "[!] ERROR: wazuh-certificates.tar not found in current directory" >&2
    exit 1
  fi

  mkdir -p /etc/filebeat/certs
  tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs "./${NODE_NAME}.pem" "./${NODE_NAME}-key.pem" "./root-ca.pem"
  mv -n /etc/filebeat/certs/${NODE_NAME}.pem /etc/filebeat/certs/filebeat.pem
  mv -n /etc/filebeat/certs/${NODE_NAME}-key.pem /etc/filebeat/certs/filebeat-key.pem

  chmod 500 /etc/filebeat/certs
  chmod 400 /etc/filebeat/certs/*
  chown -R root:root /etc/filebeat/certs

  # You must edit /etc/filebeat/filebeat.yml manually (or via script) to set output.elasticsearch, SSL settings etc.

  systemctl daemon-reload
  systemctl enable wazuh-manager filebeat
  systemctl start wazuh-manager filebeat

  echo "[*] Wazuh server setup done."
  exit 0
fi

# 3C. If installing dashboard
if [[ "$ROLE" == "dashboard" ]]; then
  echo "[*] Installing Wazuh dashboard..."
  apt-get install -y wazuh-dashboard

  echo "[*] Expecting wazuh-certificates.tar in current dir"
  if [[ ! -f ./wazuh-certificates.tar ]]; then
    echo "[!] ERROR: wazuh-certificates.tar not found" >&2
    exit 1
  fi

  mkdir -p /etc/wazuh-dashboard/certs
  tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs "./${NODE_NAME}.pem" "./${NODE_NAME}-key.pem" "./root-ca.pem"
  mv -n /etc/wazuh-dashboard/certs/${NODE_NAME}.pem /etc/wazuh-dashboard/certs/dashboard.pem
  mv -n /etc/wazuh-dashboard/certs/${NODE_NAME}-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem

  chmod 500 /etc/wazuh-dashboard/certs
  chmod 400 /etc/wazuh-dashboard/certs/*
  chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

  systemctl daemon-reload
  systemctl enable wazuh-dashboard
  systemctl start wazuh-dashboard

  echo "[*] Dashboard installed; you must edit /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml to point to your server."
  exit 0
fi

echo "[!] Unknown role: $ROLE"
exit 2
