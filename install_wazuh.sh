#!/usr/bin/env bash
# ==============================================
# Wazuh Full Clean Installer for Ubuntu
# (Manager + Indexer + Dashboard)
# Hardened + 3s pause between major steps
# ==============================================

set -euo pipefail
IFS=$'\n\t'

# Colors
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
BLUE="\e[34m"
RESET="\e[0m"

PAUSE=3   # seconds to wait between major steps

info(){ echo -e "${BLUE}[INFO]${RESET} $*"; }
step(){ echo -e "${YELLOW}[STEP]${RESET} $*"; }
ok(){ echo -e "${GREEN}[OK]${RESET} $*"; }
err(){ echo -e "${RED}[ERROR]${RESET} $*"; }

sleep_step(){ sleep "${PAUSE}"; }

trap 'err "An unexpected error occurred. Exiting."; exit 1' ERR INT

info "Starting Wazuh Full Clean Installation..."

# 0 - Require root
if [ "$EUID" -ne 0 ]; then
  err "This script must be run as root. Use: sudo ./install_wazuh.sh"
  exit 2
fi

# 1 - Stop services if present (best-effort)
step "Stopping any running Wazuh services..."
systemctl stop wazuh-manager wazuh-agent wazuh-indexer wazuh-dashboard 2>/dev/null || true
sleep_step

# 2 - Remove old repo files
step "Cleaning old Wazuh repository entries..."
rm -f /etc/apt/sources.list.d/wazuh* 2>/dev/null || true
find /etc/apt/sources.list.d/ -maxdepth 1 -type f -name '* *' -exec rm -f {} \; 2>/dev/null || true
sleep_step

# 3 - Purge old Wazuh packages and directories
step "Removing old Wazuh packages and directories..."
dpkg --remove --force-all wazuh-manager wazuh-agent wazuh-indexer wazuh-dashboard 2>/dev/null || true
rm -rf /var/ossec /etc/wazuh-indexer /etc/wazuh-dashboard /var/log/wazuh* \
       /usr/share/wazuh-dashboard /var/lib/wazuh-indexer /var/lib/wazuh 2>/dev/null || true
sleep_step

# 4 - System update & prerequisites
step "Updating system and installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y || true
apt-get install -y curl gnupg apt-transport-https lsb-release
sleep_step

# 5 - Prepare keyrings
step "Preparing keyrings directory..."
mkdir -p /usr/share/keyrings
sleep_step

# 6 - Add Wazuh GPG key with fingerprint verification
step "Fetching and installing Wazuh GPG key..."
TMPKEY="$(mktemp -p /tmp wazuh_key.XXXXXX)"
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "${TMPKEY}"
gpg --dearmor < "${TMPKEY}" > /usr/share/keyrings/wazuh.gpg
rm -f "${TMPKEY}"

# Verify fingerprint
if gpg --show-keys /usr/share/keyrings/wazuh.gpg | grep -q "96B3EE5F29111145"; then
  ok "Wazuh GPG key imported and verified."
else
  err "Wazuh GPG key verification failed!"
  exit 3
fi
sleep_step

# 7 - Add Wazuh repo
step "Adding Wazuh repository..."
cat > /etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main
EOF
chmod 644 /etc/apt/sources.list.d/wazuh.list
sleep_step

# 8 - Update package lists
step "Refreshing apt package lists..."
apt-get clean
apt-get update -y
sleep_step

# 9 - Install Wazuh packages with retries
step "Installing Wazuh Manager, Indexer, and Dashboard..."
MAX_TRIES=3
for i in $(seq 1 $MAX_TRIES); do
  if apt-get install -y wazuh-manager wazuh-indexer wazuh-dashboard; then
    ok "Wazuh packages installed."
    break
  elif [ "$i" -eq "$MAX_TRIES" ]; then
    err "Failed to install Wazuh after $MAX_TRIES attempts."
    exit 4
  else
    err "Install attempt $i failed, retrying in 5s..."
    sleep 5
    apt-get update -y || true
  fi
done
sleep_step

# 10 - Enable and start services
step "Enabling and starting Wazuh services..."
systemctl daemon-reload
systemctl enable --now wazuh-manager wazuh-indexer wazuh-dashboard
sleep_step

# 11 - Check ports
step "Checking listening ports (1514, 1515, 443)..."
ss -tulpn | grep -E '1514|1515|443' || true
sleep_step

# 12 - Dashboard info
step "Retrieving dashboard credentials..."
DASH_PASS_FILE="/etc/wazuh-dashboard/wazuh-dashboard-passwords.txt"
if [ -f "${DASH_PASS_FILE}" ]; then
  DASH_PASS=$(grep -i '^admin' "${DASH_PASS_FILE}" | awk '{print $2}' || echo "")
  echo -e "${BLUE}====================================================${RESET}"
  echo -e "${GREEN}🌍 Wazuh Dashboard is ready!${RESET}"
  echo -e "${YELLOW}URL: ${RESET}https://$(hostname -I | awk '{print $1}')"
  echo -e "${YELLOW}User: ${RESET}admin"
  echo -e "${YELLOW}Password: ${RESET}${RED}${DASH_PASS:-Not found}${RESET}"
  echo -e "${BLUE}====================================================${RESET}"
else
  echo -e "${RED}Dashboard password file not found at ${DASH_PASS_FILE}.${RESET}"
  echo -e "${BLUE}Try: https://$(hostname -I | awk '{print $1}')${RESET}"
fi
sleep_step

echo -e "${GREEN}✅ Installation script finished successfully.${RESET}"
echo -e "${BLUE}Note: Accept the SSL warning in your browser (self-signed certificate).${RESET}"
exit 0
