#!/bin/bash
# ==============================================
# Wazuh Full Clean Installer for Ubuntu
# (Manager + Indexer + Dashboard)
# ==============================================

# Colors
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
BLUE="\e[34m"
RESET="\e[0m"

echo -e "${BLUE}Starting Wazuh Full Clean Installation...${RESET}"

# 1️⃣ Remove any existing Wazuh installation
echo -e "${YELLOW}Removing existing Wazuh packages (if any)...${RESET}"
sudo systemctl stop wazuh-manager wazuh-agent wazuh-dashboard wazuh-indexer 2>/dev/null
sudo dpkg --remove --force-all wazuh-manager wazuh-agent wazuh-indexer wazuh-dashboard 2>/dev/null || true
sudo rm -rf /var/ossec /etc/wazuh-indexer /etc/wazuh-dashboard /var/log/wazuh* /usr/share/wazuh-dashboard /var/lib/wazuh-indexer

# 2️⃣ Update system
echo -e "${YELLOW}Updating system...${RESET}"
sudo apt-get update -y && sudo apt-get upgrade -y

# 3️⃣ Add Wazuh repository and GPG key
echo -e "${YELLOW}Adding Wazuh repository and GPG key...${RESET}"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# 4️⃣ Update package lists
echo -e "${YELLOW}Updating package lists...${RESET}"
sudo apt-get update -y

# 5️⃣ Install full Wazuh stack
echo -e "${YELLOW}Installing Wazuh Manager, Indexer, and Dashboard...${RESET}"
sudo apt-get install -y wazuh-manager wazuh-indexer wazuh-dashboard

# 6️⃣ Enable and start all services
echo -e "${YELLOW}Enabling and starting Wazuh services...${RESET}"
sudo systemctl enable --now wazuh-manager
sudo systemctl enable --now wazuh-indexer
sudo systemctl enable --now wazuh-dashboard

# 7️⃣ Check listening ports
echo -e "${YELLOW}Checking ports...${RESET}"
sudo ss -tulpn | grep -E '1514|1515|443'

# 8️⃣ Display dashboard login info
echo -e "${GREEN}Installation complete!${RESET}"

if [ -f /etc/wazuh-dashboard/wazuh-dashboard-passwords.txt ]; then
    DASH_PASS=$(sudo grep "admin" /etc/wazuh-dashboard/wazuh-dashboard-passwords.txt | awk '{print $2}')
    echo -e "${BLUE}====================================================${RESET}"
    echo -e "${GREEN}🌍 Wazuh Dashboard is ready!${RESET}"
    echo -e "${YELLOW}URL: ${RESET}https://$(hostname -I | awk '{print $1}')"
    echo -e "${YELLOW}User: ${RESET}admin"
    echo -e "${YELLOW}Password: ${RESET}${RED}$DASH_PASS${RESET}"
    echo -e "${BLUE}====================================================${RESET}"
else
    echo -e "${RED}Dashboard password file not found. Use default login: admin/admin${RESET}"
fi

echo -e "${BLUE}Note: Accept the SSL warning in browser since it uses a self-signed certificate.${RESET}"
