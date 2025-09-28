#!/bin/bash

# Exit on any error
set -e

# Variables
WAZUH_VERSION="4.13"
NODE_NAME="wazuh-1"
DASHBOARD_NODE_NAME="dashboard"

# Update system
echo "Updating system..."
apt-get update && apt-get upgrade -y

# Install required packages
echo "Installing required packages..."
apt-get install -y gnupg apt-transport-https curl debhelper tar libcap2-bin

# Add Wazuh GPG key and repository
echo "Adding Wazuh GPG key and repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_VERSION}/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

# Update package list
apt-get update

# Install Wazuh manager
echo "Installing Wazuh manager..."
apt-get install -y wazuh-manager

# Install Filebeat
echo "Installing Filebeat..."
apt-get install -y filebeat

# Configure Filebeat to forward logs to Wazuh indexer
echo "Configuring Filebeat..."
cat <<EOF > /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/*.log

output.elasticsearch:
  hosts: ["https://127.0.0.1:9200"]
  username: "admin"
  password: "admin"
  ssl.certificate_authorities: ["/etc/wazuh-manager/certs/root-ca.pem"]
  ssl.certificate: "/etc/wazuh-manager/certs/admin.pem"
  ssl.key: "/etc/wazuh-manager/certs/admin-key.pem"
EOF

# Enable and start Filebeat
systemctl enable filebeat
systemctl start filebeat

# Install Wazuh indexer
echo "Installing Wazuh indexer..."
apt-get install -y wazuh-indexer

# Configure Wazuh indexer
echo "Configuring Wazuh indexer..."
cat <<EOF > /etc/wazuh-indexer/opensearch.yml
network.host: 0.0.0.0
node.name: ${NODE_NAME}
cluster.initial_master_nodes: ["${NODE_NAME}"]
discovery.seed_hosts: ["127.0.0.1"]
plugins.security.nodes_dn:
  - "CN=${NODE_NAME},OU=Wazuh,O=Wazuh,L=California,C=US"
EOF

# Start Wazuh indexer
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

# Install Wazuh dashboard
echo "Installing Wazuh dashboard..."
apt-get install -y wazuh-dashboard

# Configure Wazuh dashboard
echo "Configuring Wazuh dashboard..."
cat <<EOF > /etc/wazuh-dashboard/opensearch_dashboards.yml
server.host: "0.0.0.0"
server.port: 443
opensearch.hosts: ["https://127.0.0.1:9200"]
ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
EOF

# Enable and start Wazuh dashboard
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

# Output installation summary
echo "Wazuh installation completed successfully!"
echo "You can access the Wazuh dashboard at https://<YOUR_SERVER_IP>"
