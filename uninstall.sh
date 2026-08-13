#!/bin/bash

# Next.js Automated Uninstall Script
# Run as root or with sudo

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root or with sudo"
fi

log_step "Project Selection"
read -p "Enter the project name to uninstall (e.g., nextjs-app): " PROJECT_NAME
if [[ -z "$PROJECT_NAME" ]]; then
    log_error "Project name cannot be empty."
fi

read -p "Enter the domain name associated with this project (e.g., example.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    log_error "Domain name cannot be empty."
fi

echo ""
log_warn "⚠️  WARNING: This will completely delete the following:"
echo "  - Project directory: /var/www/$PROJECT_NAME"
echo "  - Backups directory: /var/backups/$PROJECT_NAME"
echo "  - Systemd service: $PROJECT_NAME.service"
echo "  - Nginx configurations for $DOMAIN"
echo "  - SSL Certificates for $DOMAIN"
echo "  - MariaDB database and user (if applicable)"
echo ""
read -p "Are you absolutely sure you want to proceed? (Type 'YES' to confirm): " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
    log_error "Uninstallation aborted by user."
fi

log_step "Stopping and Removing Service"
if systemctl list-unit-files | grep -q "^$PROJECT_NAME.service"; then
    systemctl stop "$PROJECT_NAME" 2>/dev/null || true
    systemctl disable "$PROJECT_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/$PROJECT_NAME.service"
    systemctl daemon-reload
    log_info "Service $PROJECT_NAME stopped and removed."
else
    log_info "Service $PROJECT_NAME not found. Skipping."
fi

log_step "Removing Nginx Configuration"
NGINX_AVAILABLE="/etc/nginx/sites-available/$DOMAIN"
NGINX_ENABLED="/etc/nginx/sites-enabled/$DOMAIN"

if [[ -f "$NGINX_AVAILABLE" || -f "$NGINX_ENABLED" ]]; then
    rm -f "$NGINX_AVAILABLE"
    rm -f "$NGINX_ENABLED"
    log_info "Nginx site configurations removed."
else
    log_info "Nginx site configurations not found. Skipping."
fi

# Clean up injected rate limit zones from the main nginx.conf
log_info "Cleaning up rate limiting zones from global Nginx config..."
sed -i "/zone=${PROJECT_NAME}_api/d" /etc/nginx/nginx.conf
sed -i "/zone=${PROJECT_NAME}_general/d" /etc/nginx/nginx.conf

# Reload Nginx to apply changes safely
if command -v nginx &> /dev/null; then
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        log_info "Nginx reloaded."
    else
        log_warn "Nginx config test failed. Skipping reload. Please check your Nginx configuration manually."
    fi
fi

log_step "Removing SSL Certificates"
if command -v certbot &> /dev/null; then
    if certbot certificates 2>/dev/null | grep -q "Certificate Name: $DOMAIN"; then
        certbot delete --cert-name "$DOMAIN" --non-interactive || true
        log_info "SSL certificates for $DOMAIN deleted."
    else
        log_info "No Let's Encrypt certificates found for $DOMAIN. Skipping."
    fi
fi

log_step "Removing Database"
DB_NAME="${PROJECT_NAME//-/_}_db"
DB_USER="${PROJECT_NAME//-/_}_user"

if command -v mysql &> /dev/null; then
    if mysql -e "USE $DB_NAME;" 2>/dev/null; then
        mysql -e "DROP DATABASE IF EXISTS $DB_NAME;"
        mysql -e "DROP USER IF EXISTS '$DB_USER'@'localhost';"
        mysql -e "FLUSH PRIVILEGES;"
        log_info "MariaDB database ($DB_NAME) and user ($DB_USER) removed."
    else
        log_info "MariaDB database $DB_NAME not found (or SQLite was used). Skipping."
    fi
fi

log_step "Removing Directories"
if [[ -d "/var/www/$PROJECT_NAME" ]]; then
    rm -rf "/var/www/$PROJECT_NAME"
    log_info "Project directory /var/www/$PROJECT_NAME removed."
else
    log_info "Project directory /var/www/$PROJECT_NAME not found. Skipping."
fi

if [[ -d "/var/backups/$PROJECT_NAME" ]]; then
    rm -rf "/var/backups/$PROJECT_NAME"
    log_info "Backups directory /var/backups/$PROJECT_NAME removed."
else
    log_info "Backups directory not found. Skipping."
fi

echo ""
echo "=========================================="
log_info "🗑️ Uninstallation of $PROJECT_NAME completed successfully!"
echo "=========================================="