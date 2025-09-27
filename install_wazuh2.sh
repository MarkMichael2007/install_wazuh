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

# 0 - require root
if [ "$EUID" -ne 0 ]; then
  err "This script must be run as root. Use sudo ./install_wazuh.sh"
  exit 2
fi

# 1 - Stop services if present (best-effort)
step "Stopping any running Wazuh services (if present)..."
systemctl stop wazuh-manager.service 2>/dev/null || true
systemctl stop wazuh-agent.service 2>/dev/null || true
systemctl stop wazuh-indexer.service 2>/dev/null || true
systemctl stop wazuh-dashboard.service 2>/dev/null || true
sleep_step

# 2 - Remove broken or stale Wazuh source files
step "Removing stale/invalid Wazuh source files from /etc/apt/sources.list.d/ (safe cleanup)..."
# Remove any file that begins with 'wazuh' (including trailing-space variants)
rm -f /etc/apt/sources.list.d/wazuh* 2>/dev/null || true
# Also try to remove obvious bad names with spaces (best-effort)
find /etc/apt/sources.list.d/ -maxdepth 1 -type f -name '* *' -exec rm -f {} \; 2>/dev/null || true
sleep_step

# 3 - Purge dpkg packages (best-effort)
step "Removing Wazuh packages and leftover directories (best-effort)..."
# Try to remove packages forcibly without failing the script if they don't exist
dpkg --remove --force-all wazuh-manager wazuh-agent wazuh-indexer wazuh-dashboard 2>/dev/null || true
# Remove leftovers
rm -rf /var/ossec /etc/wazuh-indexer /etc/wazuh-dashboard /var/log/wazuh* /usr/share/wazuh-dashboard /var/lib/wazuh-indexer /var/lib/wazuh 2>/dev/null || true
sleep_step

# 4 - Update system package lists and upgrade
step "Updating system package lists and upgrading packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
# upgrade but allow it to continue without interactive prompts
apt-get -y upgrade || true
sleep_step

# 5 - Ensure /usr/share/keyrings exists
step "Preparing keyrings directory..."
mkdir -p /usr/share/keyrings
sleep_step

# 6 - Add Wazuh GPG key safely (write to temp, then move to target to avoid interactive overwrite)
step "Fetching Wazuh GPG key and installing to /usr/share/keyrings/wazuh.gpg..."
TMPKEY="$(mktemp -p /tmp wazuh_key.XXXXXX)"
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "${TMPKEY}" || { rm -f "${TMPKEY}"; err "Failed to fetch GPG key"; exit 3; }
# dearmor to a temp file then move
TMPDEARMOR="$(mktemp -p /tmp wazuh_key_dearmor.XXXXXX)"
gpg --dearmor < "${TMPKEY}" > "${TMPDEARMOR}" || { rm -f "${TMPKEY}" "${TMPDEARMOR}"; err "gpg --dearmor failed"; exit 4; }
mv -f "${TMPDEARMOR}" /usr/share/keyrings/wazuh.gpg
rm -f "${TMPKEY}"
ok "GPG key installed."
sleep_step

# 7 - Add repository file (atomic write)
step "Writing Wazuh apt repository to /etc/apt/sources.list.d/wazuh.list..."
cat > /etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main
EOF
# Ensure file has no trailing whitespace in its filename (we removed earlier)
chmod 644 /etc/apt/sources.list.d/wazuh.list
sleep_step

# 8 - Update package lists after adding repo
step "Updating apt package lists after adding Wazuh repository..."
apt-get update
sleep_step

# 9 - Install Wazuh components
step "Installing Wazuh Manager, Indexer, and Dashboard (this may take a while)..."
# Try installing with retries
MAX_TRIES=3
count=0
while [ "$count" -lt "$MAX_TRIES" ]; do
  if apt-get -y install wazuh-manager wazuh-indexer wazuh-dashboard; then
    ok "Wazuh packages installed."
    break
  else
    count=$((count+1))
    err "Install attempt ${count} failed. Retrying in 5s..."
    sleep 5
    apt-get update || true
  fi
  if [ "$count" -ge "$MAX_TRIES" ]; then
    err "Package installation failed after ${MAX_TRIES} attempts. Exiting."
    exit 5
  fi
done
sleep_step

# 10 - Enable & start services
step "Enabling and starting Wazuh services..."
systemctl daemon-reload
systemctl enable --now wazuh-manager.service || true
systemctl enable --now wazuh-indexer.service || true
systemctl enable --now wazuh-dashboard.service || true
sleep_step

# 11 - Check listening ports (look for manager (1514/1515), dashboard (443) and indexer)
step "Checking listening ports (1514, 1515, 443)..."
ss -tulpn | grep -E '1514|1515|443' || true
sleep_step

# 12 - Output dashboard access info
step "Displaying Dashboard login info (if available)..."
DASH_PASS_FILE="/etc/wazuh-dashboard/wazuh-dashboard-passwords.txt"
if [ -f "${DASH_PASS_FILE}" ]; then
  # try to extract admin password
  DASH_PASS=$(grep -i '^admin' "${DASH_PASS_FILE}" | awk '{print $2}' || echo "")
  echo -e "${BLUE}====================================================${RESET}"
  echo -e "${GREEN}🌍 Wazuh Dashboard is ready!${RESET}"
  echo -e "${YELLOW}URL: ${RESET}https://$(hostname -I | awk '{print $1}')"
  echo -e "${YELLOW}User: ${RESET}admin"
  if [ -n "${DASH_PASS}" ]; then
    echo -e "${YELLOW}Password: ${RESET}${RED}${DASH_PASS}${RESET}"
  else
    echo -e "${YELLOW}Password: ${RESET}${RED}(admin password not found in ${DASH_PASS_FILE})${RESET}"
  fi
  echo -e "${BLUE}====================================================${RESET}"
else
  echo -e "${RED}Dashboard password file not found at ${DASH_PASS_FILE}. Default may be admin/admin or dashboard setup created its own password.${RESET}"
  echo -e "${BLUE}Try: https://$(hostname -I | awk '{print $1}')${RESET}"
fi
sleep_step

echo -e "${GREEN}Installation script finished.${RESET}"
echo -e "${BLUE}Note: Accept the SSL warning in your browser since the dashboard uses a self-signed certificate by default.${RESET}"

# End
exit 0
