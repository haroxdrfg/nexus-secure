#!/bin/bash

################################################################################
# NEXUS SECURE v2.2.0 - Production Deployment Setup Script
# 
# Purpose: Automate Let's Encrypt certificate setup + production configuration
# Usage: sudo bash deploy-production.sh
# 
# Requirements:
#   - Ubuntu 22.04+ or similar Debian-based system
#   - Domain registered and DNS A record pointing to this server IP
#   - Ports 80 and 443 open in firewall
#   - sudo access
#
################################################################################

set -e  # Exit on error

echo "════════════════════════════════════════════════════════════════"
echo "  NEXUS SECURE v2.2.0 - PRODUCTION DEPLOYMENT"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root (use: sudo bash deploy-production.sh)${NC}"
   exit 1
fi

# ============================================================================
# STEP 1: Collect input
# ============================================================================

echo -e "${YELLOW}Step 1: Configuration Input${NC}"
echo "─────────────────────────────────────────"

read -p "Enter production domain (e.g., nexus-secure.com): " DOMAIN

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}❌ Domain cannot be empty${NC}"
    exit 1
fi

read -p "Enter admin email for Let's Encrypt (e.g., admin@example.com): " ADMIN_EMAIL

if [ -z "$ADMIN_EMAIL" ]; then
    echo -e "${RED}❌ Email cannot be empty${NC}"
    exit 1
fi

read -p "Enter Node.js app port (default: 3000): " APP_PORT
APP_PORT=${APP_PORT:-3000}

echo ""
echo -e "${GREEN}✓ Configuration:${NC}"
echo "  Domain: $DOMAIN"
echo "  Email: $ADMIN_EMAIL"
echo "  App Port: $APP_PORT"
echo ""

# ============================================================================
# STEP 2: Install dependencies
# ============================================================================

echo -e "${YELLOW}Step 2: Installing Dependencies${NC}"
echo "─────────────────────────────────────────"

# Update system
echo "📦 Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "📦 Installing Node.js 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    apt-get install -y -qq nodejs
else
    NODE_VERSION=$(node --version)
    echo "✓ Node.js already installed: $NODE_VERSION"
fi

# Install Nginx
if ! command -v nginx &> /dev/null; then
    echo "📦 Installing Nginx..."
    apt-get install -y -qq nginx
else
    echo "✓ Nginx already installed"
fi

# Install Certbot for Let's Encrypt
if ! command -v certbot &> /dev/null; then
    echo "📦 Installing Certbot..."
    apt-get install -y -qq certbot python3-certbot-nginx
else
    echo "✓ Certbot already installed"
fi

# Install PM2 for process management
if ! command -v pm2 &> /dev/null; then
    echo "📦 Installing PM2..."
    npm install -g pm2 -qq
else
    echo "✓ PM2 already installed"
fi

echo -e "${GREEN}✓ All dependencies installed${NC}"
echo ""

# ============================================================================
# STEP 3: Configure Nginx
# ============================================================================

echo -e "${YELLOW}Step 3: Configuring Nginx${NC}"
echo "─────────────────────────────────────────"

# Create Nginx config
NGINX_CONFIG="/etc/nginx/sites-available/$DOMAIN"

echo "📝 Creating Nginx configuration for $DOMAIN..."

sudo tee $NGINX_CONFIG > /dev/null <<EOF
# NEXUS SECURE v2.2.0 - Nginx Reverse Proxy Configuration
# Auto-generated for $DOMAIN on $(date)

# Rate limiting zone (100 requests/minute per IP)
limit_req_zone \$binary_remote_addr zone=nexus_ip_limit:10m rate=100r/m;
limit_req_zone \$http_x_forwarded_for zone=nexus_identity_limit:10m rate=50r/m;

# HTTP redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;

    # Certbot ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;

    # SSL certificates (will be installed by certbot)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Rate limiting (both IP and identity must pass)
    limit_req zone=nexus_ip_limit burst=10 nodelay;
    limit_req zone=nexus_identity_limit burst=5 nodelay;

    # Upstream app server
    upstream nexus_app {
        server 127.0.0.1:$APP_PORT;
        keepalive 64;
    }

    # Reverse proxy to Node.js app
    location / {
        proxy_pass https://nexus_app;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Logging
    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log /var/log/nginx/$DOMAIN.error.log;
}
EOF

# Enable site
echo "🔗 Enabling Nginx configuration..."
sudo ln -sf $NGINX_CONFIG /etc/nginx/sites-enabled/$DOMAIN

# Test Nginx config
echo "✓ Testing Nginx configuration..."
if sudo nginx -t > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Nginx configuration valid${NC}"
else
    echo -e "${RED}❌ Nginx configuration error, review manually${NC}"
    exit 1
fi

# Restart Nginx
echo "↻ Restarting Nginx..."
sudo systemctl restart nginx

echo -e "${GREEN}✓ Nginx configured${NC}"
echo ""

# ============================================================================
# STEP 4: Setup Let's Encrypt
# ============================================================================

echo -e "${YELLOW}Step 4: Setting Up Let's Encrypt SSL${NC}"
echo "─────────────────────────────────────────"

# Create certbot root directory
sudo mkdir -p /var/www/certbot

# Request certificate
echo "🔐 Requesting Let's Encrypt certificate for $DOMAIN..."
sudo certbot certonly --nginx \
    -d $DOMAIN \
    -d www.$DOMAIN \
    --non-interactive \
    --agree-tos \
    --email $ADMIN_EMAIL \
    --no-eff-email 2>&1 || {
        echo -e "${RED}❌ Certbot setup failed. Check:${NC}"
        echo "  1. Domain is registered and DNS configured"
        echo "  2. A record points to this IP: $(hostname -I)"
        echo "  3. Ports 80 and 443 are open in firewall"
        exit 1
    }

echo -e "${GREEN}✓ SSL certificate obtained${NC}"
echo ""

# ============================================================================
# STEP 5: Configure Auto-Renewal
# ============================================================================

echo -e "${YELLOW}Step 5: Setting Up Certificate Auto-Renewal${NC}"
echo "─────────────────────────────────────────"

# Create renewal cron job
echo "📅 Creating auto-renewal cron job..."
sudo tee /etc/cron.d/certbot-nexus > /dev/null <<EOF
# Let's Encrypt auto-renewal for NEXUS SECURE
0 3 * * * root /usr/bin/certbot renew --quiet --no-eff-email && systemctl reload nginx
EOF

echo -e "${GREEN}✓ Auto-renewal configured (daily at 3 AM UTC)${NC}"
echo ""

# ============================================================================
# STEP 6: Setup Node.js App Directory
# ============================================================================

echo -e "${YELLOW}Step 6: Preparing Application Directory${NC}"
echo "─────────────────────────────────────────"

# Create app directory if not exists
APP_DIR="/opt/nexus-secure"
if [ ! -d "$APP_DIR" ]; then
    echo "📁 Creating application directory: $APP_DIR"
    sudo mkdir -p $APP_DIR
else
    echo "✓ Application directory exists: $APP_DIR"
fi

# Create data and logs directories
sudo mkdir -p $APP_DIR/data
sudo mkdir -p $APP_DIR/logs
sudo mkdir -p $APP_DIR/certs

# Set permissions
echo "🔐 Setting up permissions..."
sudo chown -R nobody:nogroup $APP_DIR
sudo chmod 755 $APP_DIR
sudo chmod 755 $APP_DIR/data
sudo chmod 755 $APP_DIR/logs
sudo chmod 700 $APP_DIR/certs

echo -e "${GREEN}✓ Application directory prepared${NC}"
echo ""

# ============================================================================
# STEP 7: Create Environment File
# ============================================================================

echo -e "${YELLOW}Step 7: Creating Production Environment${NC}"
echo "─────────────────────────────────────────"

# Generate random secrets
JWT_SECRET=$(openssl rand -hex 32)
MASTER_SECRET=$(openssl rand -hex 32)

# Create .env file
ENV_FILE="$APP_DIR/.env"
echo "📝 Creating production .env file..."

sudo tee $ENV_FILE > /dev/null <<EOF
# NEXUS SECURE v2.2.0 - Production Environment
# Generated: $(date)

NODE_ENV=production
PORT=$APP_PORT
HOSTNAME=127.0.0.1

TLS_CERT_PATH=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/$DOMAIN/privkey.pem

PRODUCTION_DOMAIN=$DOMAIN
ALLOWED_ORIGINS=https://$DOMAIN,https://www.$DOMAIN

JWT_SECRET=$JWT_SECRET
MASTER_SECRET=$MASTER_SECRET

MESSAGE_TTL=120000

RATE_LIMIT_IP=100
RATE_LIMIT_IDENTITY=50

DATABASE_PATH=$APP_DIR/data/nexus-secure.db
AUDIT_LOG_PATH=$APP_DIR/logs/audit.log

E2E_ENABLED=true
FORWARD_SECRECY_ENABLED=true
AUDIT_LOGGING_ENABLED=true
RATE_LIMITING_ENABLED=true

LOG_LEVEL=info
LOG_FILE=$APP_DIR/logs/server.log
EOF

sudo chmod 600 $ENV_FILE
echo -e "${GREEN}✓ Environment file created (.env permissions: 0600)${NC}"
echo ""

# ============================================================================
# STEP 8: Setup PM2 Service
# ============================================================================

echo -e "${YELLOW}Step 8: Configuring PM2 Process Manager${NC}"
echo "─────────────────────────────────────────"

# Create PM2 config
PM2_CONFIG="$APP_DIR/ecosystem.config.js"
echo "📝 Creating PM2 configuration..."

sudo tee $PM2_CONFIG > /dev/null <<'EOF'
module.exports = {
  apps: [{
    name: 'nexus-secure',
    script: 'server.js',
    cwd: '/opt/nexus-secure',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    },
    error_file: '/opt/nexus-secure/logs/pm2-error.log',
    out_file: '/opt/nexus-secure/logs/pm2-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G'
  }]
};
EOF

echo -e "${GREEN}✓ PM2 configuration created${NC}"
echo ""

# ============================================================================
# STEP 9: Firewall Configuration
# ============================================================================

echo -e "${YELLOW}Step 9: Configuring Firewall (UFW)${NC}"
echo "─────────────────────────────────────────"

if command -v ufw &> /dev/null; then
    echo "🔥 Setting up firewall rules..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow 22/tcp    # SSH
    sudo ufw allow 80/tcp    # HTTP (Let's Encrypt)
    sudo ufw allow 443/tcp   # HTTPS
    sudo ufw limit 22/tcp    # Rate limit SSH
    sudo ufw --force enable > /dev/null 2>&1
    echo -e "${GREEN}✓ Firewall configured${NC}"
else
    echo -e "${YELLOW}⚠ UFW not installed, skipping firewall setup${NC}"
fi
echo ""

# ============================================================================
# STEP 10: Monitoring & Logging
# ============================================================================

echo -e "${YELLOW}Step 10: Setting Up Monitoring${NC}"
echo "─────────────────────────────────────────"

# Create monitoring script
MONITOR_SCRIPT="$APP_DIR/monitor.sh"
sudo tee $MONITOR_SCRIPT > /dev/null <<'EOF'
#!/bin/bash
# Monitor NEXUS SECURE health

APP_DIR="/opt/nexus-secure"
LOG_DIR="$APP_DIR/logs"
AUDIT_LOG="$LOG_DIR/audit.log"

echo "NEXUS SECURE v2.2.0 - System Health"
echo "===================================="
echo ""

echo "System Status:"
uptime

echo ""
echo "Node.js Process:"
pm2 status

echo ""
echo "Disk Usage:"
df -h $APP_DIR | tail -1

echo ""
echo "Recent Audit Logs (last 10 entries):"
tail -10 $AUDIT_LOG

echo ""
echo "Certificate Status:"
certbot certificates 2>/dev/null | grep "$PRODUCTION_DOMAIN" || echo "No certificate found"
EOF

sudo chmod +x $MONITOR_SCRIPT

echo -e "${GREEN}✓ Monitoring script created: $MONITOR_SCRIPT${NC}"
echo ""

# ============================================================================
# STEP 11: Summary & Next Steps
# ============================================================================

echo "════════════════════════════════════════════════════════════════"
echo -e "${GREEN}✓ PRODUCTION SETUP COMPLETE${NC}"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📋 IMPORTANT - Save These Secrets Securely:"
echo "   JWT_SECRET: $JWT_SECRET"
echo "   MASTER_SECRET: $MASTER_SECRET"
echo ""
echo "🚀 NEXT STEPS:"
echo "   1. Copy app files to: /opt/nexus-secure/"
echo "      scp -r . user@server:/opt/nexus-secure/"
echo ""
echo "   2. Install dependencies:"
echo "      cd /opt/nexus-secure && npm install --production"
echo ""
echo "   3. Start the application with PM2:"
echo "      pm2 start ecosystem.config.js"
echo "      pm2 save"
echo "      pm2 startup"
echo ""
echo "   4. Monitor application:"
echo "      pm2 logs nexus-secure"
echo "      tail -f /opt/nexus-secure/logs/audit.log"
echo ""
echo "   5. Verify certificate:"
echo "      sudo certbot certificates"
echo ""
echo "✅ SSL Certificate: $DOMAIN"
echo "✅ Auto-renewal: Daily at 3 AM UTC"
echo "✅ Nginx: Reverse proxy configured"
echo "✅ Firewall: Ports 22, 80, 443 open"
echo "✅ Environment: .env file created (permissions: 0600)"
echo ""
echo "🔒 Security Reminders:"
echo "   • Never commit .env to version control"
echo "   • Keep secrets in secure vault (not files)"
echo "   • Rotate JWT_SECRET and MASTER_SECRET periodically"
echo "   • Monitor audit logs for anomalies"
echo "   • Backup database and audit logs daily"
echo ""
echo "📞 Support:"
echo "   Check \$PWD/E2E-INTEGRATION-GUIDE.md for integration details"
echo "   Check \$PWD/E2E-STATUS-REPORT.md for full status"
echo ""
