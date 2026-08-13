PROJECT_DIR="/var/www/$PROJECT_NAME"
NGINX_AVAILABLE="/etc/nginx/sites-available/$DOMAIN"
NGINX_ENABLED="/etc/nginx/sites-enabled/$DOMAIN"

# Check if project directory already exists
if [[ -d "$PROJECT_DIR" ]]; then
    log_warn "Project directory $PROJECT_DIR already exists."
    read -p "Do you want to remove it and continue? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        log_error "Setup cancelled by user."
    fi
    log_info "Removing existing directory..."
    rm -rf "$PROJECT_DIR"
fi

# Check if nginx site already exists
if [[ -f "$NGINX_AVAILABLE" ]]; then
    log_warn "Nginx configuration for $DOMAIN already exists."
    read -p "Do you want to overwrite it? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        log_error "Setup cancelled by user."
    fi
    rm -f "$NGINX_AVAILABLE" "$NGINX_ENABLED"
fi

# Check if service already exists
if systemctl list-unit-files | grep -q "^$PROJECT_NAME.service"; then
    log_warn "Service $PROJECT_NAME already exists."
    systemctl stop "$PROJECT_NAME" 2>/dev/null || true
    systemctl disable "$PROJECT_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/$PROJECT_NAME.service"
fi

log_info "Starting setup for $DOMAIN..."

# Update system
log_info "Updating system packages..."
apt-get update
apt-get upgrade -y

# Create swap if not exists (prevents OOM during build)
if ! swapon --show | grep -q '/swapfile'; then
    log_info "Creating 2GB swap file to prevent build failures..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    log_info "Swap created successfully"
fi

# Check available RAM
TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
if [[ $TOTAL_RAM -lt 2048 ]]; then
    log_warn "Low RAM detected (${TOTAL_RAM}MB). Build may be slow or fail."
    log_warn "Recommended: At least 2GB RAM. Current: ${TOTAL_RAM}MB"
    read -p "Continue anyway? (yes/no): " CONFIRM_RAM
    if [[ "$CONFIRM_RAM" != "yes" ]]; then
        log_error "Setup cancelled due to insufficient RAM."
    fi
    # Reduce Node memory limit for low-RAM systems
    export NODE_OPTIONS="--max-old-space-size=1024"
else
    export NODE_OPTIONS="--max-old-space-size=1536"
fi

# Install Node.js and npm if not installed
if ! command -v node &> /dev/null; then
    log_info "Installing Node.js and npm..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
else
    log_info "Node.js already installed ($(node -v))"
fi

# Install lsof if missing (required for robust port detection)
if ! command -v lsof &> /dev/null; then
    log_info "Installing lsof for port detection..."
    apt-get install -y lsof
fi

# Install nginx if not installed
if ! command -v nginx &> /dev/null; then
    log_info "Installing Nginx..."
    apt-get install -y nginx
else
    log_info "Nginx already installed"
fi

# Install certbot if not installed
if ! command -v certbot &> /dev/null; then
    log_info "Installing Certbot..."
    apt-get install -y certbot python3-certbot-nginx
else
    log_info "Certbot already installed"
fi

# Install database
if [[ "$DB_TYPE" == "mariadb" ]]; then
    if ! command -v mysql &> /dev/null; then
        log_info "Installing MariaDB..."
        apt-get install -y mariadb-server
        systemctl start mariadb
        systemctl enable mariadb
    else
        log_info "MariaDB already installed"
    fi
    
    # Check if database exists
    if mysql -e "USE $DB_NAME;" 2>/dev/null; then
        log_warn "Database $DB_NAME already exists. Dropping and recreating..."
        mysql -e "DROP DATABASE $DB_NAME;"
    fi
    
    # Secure MariaDB and create database
    log_info "Creating MariaDB database and user..."
    mysql -e "CREATE DATABASE $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -e "DROP USER IF EXISTS '$DB_USER'@'localhost';"
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    
    DB_URL="mysql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
else
    log_info "SQLite will be used (no installation needed)"
    DB_URL="file:./analytics.db"
fi

# Find a random free port between 3000 and 9000
find_free_port() {
    local port
    local attempts=0
    local max_attempts=100
    
    while [[ $attempts -lt $max_attempts ]]; do
        # Generate random port between 3000 and 9000
        port=$(shuf -i 3000-9000 -n 1)
        
        # Check if port is in use using lsof
        if ! lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo $port
            return 0
        fi
        
        attempts=$((attempts + 1))
    done
    
    log_error "Could not find a free port after $max_attempts attempts"
}

log_info "Scanning for a random available port..."
APP_PORT=$(find_free_port)
log_info "Selected available port: $APP_PORT"