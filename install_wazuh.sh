#!/usr/bin/env bash
# ==============================================
# Wazuh Full Clean Installer for Ubuntu
# (Manager + Indexer + Dashboard)
# Hardened + 3s pause between major steps
# Tries to ensure directories exist and prints admin/password
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

# Ensure basic tools exist
step "Checking for required commands (curl, gpg, ss)..."
for cmd in curl gpg ss awk sed grep mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    info "Installing missing prerequisite: $cmd"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get -y install --no-install-recommends curl gnupg dirmngr apt-transport-https ca-certificates || true
    break
  fi
done
sleep_step

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
# Remove leftovers (be conservative)
rm -rf /var/ossec /etc/wazuh-indexer /etc/wazuh-dashboard /var/log/wazuh* /usr/share/wazuh-dashboard /var/lib/wazuh-indexer /var/lib/wazuh 2>/dev/null || true
sleep_step

# 4 - Update system package lists and upgrade
step "Updating system package lists and upgrading packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade || true
sleep_step

# 5 - Ensure /usr/share/keyrings and /etc/apt/sources.list.d exist
step "Preparing directories..."
mkdir -p /usr/share/keyrings /etc/apt/sources.list.d /etc/wazuh-dashboard
chmod 755 /usr/share/keyrings /etc/apt/sources.list.d
sleep_step

# 6 - Add Wazuh GPG key safely (write to temp, then move to target to avoid interactive overwrite)
step "Fetching Wazuh GPG key and installing to /usr/share/keyrings/wazuh.gpg..."
TMPKEY="$(mktemp -p /tmp wazuh_key.XXXXXX)" || { err "mktemp failed"; exit 3; }
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "${TMPKEY}" || { rm -f "${TMPKEY}"; err "Failed to fetch GPG key"; exit 3; }
TMPDEARMOR="$(mktemp -p /tmp wazuh_key_dearmor.XXXXXX)" || { rm -f "${TMPKEY}"; err "mktemp failed"; exit 4; }
# dearmor (portable): gpg --dearmor prefers to write a binary file
if ! gpg --dearmor < "${TMPKEY}" > "${TMPDEARMOR}" 2>/dev/null; then
  rm -f "${TMPKEY}" "${TMPDEARMOR}"
  err "gpg --dearmor failed"
  exit 4
fi
mv -f "${TMPDEARMOR}" /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg
rm -f "${TMPKEY}"
ok "GPG key installed."
sleep_step

# 7 - Add repository file (atomic write)
step "Writing Wazuh apt repository to /etc/apt/sources.list.d/wazuh.list..."
cat > /etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main
EOF
chmod 644 /etc/apt/sources.list.d/wazuh.list
sleep_step

# 8 - Update package lists after adding repo
step "Updating apt package lists after adding Wazuh repository..."
apt-get update
sleep_step

# 9 - Install Wazuh components
step "Installing Wazuh Manager, Indexer, and Dashboard (this may take a while)..."
# Ensure noninteractive
export DEBIAN_FRONTEND=noninteractive
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

# 10 - Ensure basic directories and ownership are present (best-effort)
step "Ensuring expected directories & permissions..."
# Typical locations: /etc/wazuh-dashboard, /var/lib/wazuh-dashboard, /usr/share/wazuh-dashboard
mkdir -p /etc/wazuh-dashboard /var/lib/wazuh-dashboard /usr/share/wazuh-dashboard
# best-effort chown to wazuh-dashboard if user exists
if id -u wazuh-dashboard >/dev/null 2>&1; then
  chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard /var/lib/wazuh-dashboard /usr/share/wazuh-dashboard || true
fi
sleep_step

# 11 - Enable & start services
step "Enabling and starting Wazuh services..."
systemctl daemon-reload
systemctl enable --now wazuh-manager.service || true
systemctl enable --now wazuh-indexer.service || true
systemctl enable --now wazuh-dashboard.service || true
sleep_step

# 12 - Check listening ports (look for manager (1514/1515), dashboard (443) and indexer)
step "Checking listening ports (1514, 1515, 443)..."
ss -tulpn | grep -E '1514|1515|443' || true
sleep_step

# 13 - Display dashboard access info and extract/create admin password
step "Locating Dashboard admin credentials (best-effort)..."

DASH_PASS_FILE_CANDIDATES=(
  "/etc/wazuh-dashboard/wazuh-dashboard-passwords.txt"
  "/var/lib/wazuh-dashboard/wazuh-dashboard-passwords.txt"
  "/usr/share/wazuh-dashboard/wazuh-dashboard-passwords.txt"
  "/etc/wazuh-dashboard/passwords.txt"
)

FOUND_PASS=""
FOUND_FILE=""

for f in "${DASH_PASS_FILE_CANDIDATES[@]}"; do
  if [ -f "$f" ]; then
    FOUND_FILE="$f"
    # try common formats: "admin <pass>" or "admin:<pass>" or "admin=pass"
    FOUND_PASS="$(grep -i '^admin' "$f" 2>/dev/null | head -n1 | awk '{print $2}' || true)"
    if [ -z "$FOUND_PASS" ]; then
      FOUND_PASS="$(grep -i '^admin' "$f" 2>/dev/null | head -n1 | sed -n 's/^[Aa][Dd][Mm][Ii][N[:space:]:=]*//p' || true)"
    fi
    if [ -n "$FOUND_PASS" ]; then
      break
    fi
  fi
done

# If not found, generate a password and persist to canonical path (atomic write)
if [ -z "${FOUND_PASS}" ]; then
  step "Dashboard admin password not found in known files. Generating a new password and saving to /etc/wazuh-dashboard/wazuh-dashboard-passwords.txt..."
  NEWPASS="$(tr -dc 'A-Za-z0-9!@#$%_+=-' </dev/urandom | head -c 20 || echo "wazuhAdmin$(date +%s)")"
  # write atomically
  TMPPASS="$(mktemp -p /tmp wazuh_dash_pass.XXXXXX)"
  printf "admin %s\n" "${NEWPASS}" > "${TMPPASS}"
  mv -f "${TMPPASS}" /etc/wazuh-dashboard/wazuh-dashboard-passwords.txt
  chmod 600 /etc/wazuh-dashboard/wazuh-dashboard-passwords.txt
  FOUND_PASS="${NEWPASS}"
  FOUND_FILE="/etc/wazuh-dashboard/wazuh-dashboard-passwords.txt"
  ok "New dashboard password written to ${FOUND_FILE}"
  # best-effort: if we have a CLI to set the dashboard password, attempt it (non-fatal)
  if command -v wazuh-dashboard >/dev/null 2>&1; then
    info "Attempting to set dashboard admin password via wazuh-dashboard CLI (if supported)..."
    # The CLI's interface varies between versions; try common variants (all best-effort and non-fatal)
    wazuh-dashboard passwd admin "${FOUND_PASS}" 2>/dev/null || true
    wazuh-dashboard user passwd admin "${FOUND_PASS}" 2>/dev/null || true
  fi
fi

echo -e "${BLUE}====================================================${RESET}"
echo -e "${GREEN}🌍 Wazuh Dashboard access info${RESET}"
# try to pick a sensible IP (first non-loopback)
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")"
if [ -z "${HOST_IP}" ]; then
  HOST_IP="127.0.0.1"
fi
echo -e "${YELLOW}URL: ${RESET}https://${HOST_IP}"
echo -e "${YELLOW}User: ${RESET}admin"
echo -e "${YELLOW}Password: ${RESET}${RED}${FOUND_PASS}${RESET}"
echo -e "${YELLOW}Password file: ${RESET}${FOUND_FILE}"
echo -e "${BLUE}====================================================${RESET}"

sleep_step

echo -e "${GREEN}Installation script finished.${RESET}"
echo -e "${BLUE}Note: The dashboard uses a self-signed certificate by default; accept the SSL warning in your browser or install a proper certificate.${RESET}"
echo -e "${YELLOW}If you cannot login using the password above, check the actual dashboard logs: journalctl -u wazuh-dashboard -b --no-pager${RESET}"

exit 0
