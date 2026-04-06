#!/bin/bash

# NEXUS SECURE v2 - Ubuntu 24.04 Installation Script
# Usage: sudo bash install-ubuntu.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=====================================${NC}"
echo -e "${YELLOW}NEXUS SECURE v2 - Ubuntu Setup${NC}"
echo -e "${YELLOW}=====================================${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}ERROR: This script must be run as root (use: sudo bash install-ubuntu.sh)${NC}"
   exit 1
fi

# Check Ubuntu version
UBUNTU_VERSION=$(lsb_release -rs)
if [[ "$UBUNTU_VERSION" != "24.04" ]]; then
    echo -e "${YELLOW}WARNING: This script is optimized for Ubuntu 24.04, detected: $UBUNTU_VERSION${NC}"
fi

echo -e "${GREEN}[1/8] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

echo -e "${GREEN}[2/8] Installing Node.js 20 LTS...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

echo -e "${GREEN}[3/8] Installing Nginx...${NC}"
apt-get install -y nginx

echo -e "${GREEN}[4/8] Installing Certbot for SSL...${NC}"
apt-get install -y certbot python3-certbot-nginx

echo -e "${GREEN}[5/8] Creating nexus-secure user...${NC}"
if ! id -u nexus-secure > /dev/null 2>&1; then
    useradd -r -s /bin/bash -d /opt/nexus-secure nexus-secure
    echo "User created: nexus-secure"
else
    echo "User already exists: nexus-secure"
fi

echo -e "${GREEN}[6/8] Setting up application directory...${NC}"
INSTALL_DIR="/opt/nexus-secure"

# Create directory if doesn't exist
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
fi

# Copy files (adjust the source path if needed)
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$SOURCE_DIR" != "$INSTALL_DIR" ]; then
    cp -r "$SOURCE_DIR"/* "$INSTALL_DIR"/ 2>/dev/null || true
fi

# Install dependencies
cd "$INSTALL_DIR"
npm install --production

# Set ownership
chown -R nexus-secure:nexus-secure "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

echo -e "${GREEN}[7/8] Setting up systemd service...${NC}"
cp "$INSTALL_DIR/nexus-secure.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable nexus-secure

echo -e "${GREEN}[8/8] Configuring Nginx...${NC}"
# Backup existing default config
if [ -f /etc/nginx/sites-enabled/default ]; then
    mv /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.bak
fi

# Copy Nginx config
cp "$INSTALL_DIR/nginx-config.conf" /etc/nginx/sites-available/nexus-secure

echo ""
echo -e "${YELLOW}=====================================${NC}"
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "${YELLOW}=====================================${NC}"
echo ""
echo -e "${GREEN}1. Update your domain in Nginx config:${NC}"
echo "   sudo nano /etc/nginx/sites-available/nexus-secure"
echo "   Replace 'your-domain.com' with your actual domain"
echo ""
echo -e "${GREEN}2. Enable Nginx site:${NC}"
echo "   sudo ln -sf /etc/nginx/sites-available/nexus-secure /etc/nginx/sites-enabled/"
echo "   sudo nginx -t && sudo systemctl reload nginx"
echo ""
echo -e "${GREEN}3. Setup SSL with Let's Encrypt:${NC}"
echo "   sudo certbot --nginx -d your-domain.com"
echo ""
echo -e "${GREEN}4. Start the NEXUS SECURE service:${NC}"
echo "   sudo systemctl start nexus-secure"
echo ""
echo -e "${GREEN}5. Check service status:${NC}"
echo "   sudo systemctl status nexus-secure"
echo "   sudo journalctl -u nexus-secure -f"
echo ""
echo -e "${GREEN}6. View site:${NC}"
echo "   https://your-domain.com"
echo ""
echo -e "${YELLOW}SSL Certificate Auto-Renewal:${NC}"
echo "   Certbot will auto-renew certificates via systemd timer"
echo "   Check: sudo systemctl list-timers | grep certbot"
echo ""
