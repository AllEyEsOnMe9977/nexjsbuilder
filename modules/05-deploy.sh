# Create initial admin user with proper error handling
log_info "Creating admin user..."
cat > $PROJECT_DIR/create-admin.js << ADMINEOF
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function createAdmin() {
  try {
    const hash = await bcrypt.hash(process.argv[2], 12);
    const user = await prisma.user.upsert({
      where: { username: '$ADMIN_USER' },
      update: {
        password: hash
      },
      create: {
        username: '$ADMIN_USER',
        password: hash,
        role: 'admin'
      }
    });
    console.log('Admin user created/updated successfully');
  } catch (error) {
    console.error('Error creating admin user:', error);
    process.exit(1);
  } finally {
    await prisma.\$disconnect();
  }
}

createAdmin();
ADMINEOF

cd $PROJECT_DIR && node create-admin.js "$ADMIN_PASSWORD" || log_error "Failed to create admin user"
rm $PROJECT_DIR/create-admin.js

# Install dependencies and build
log_info "Installing production dependencies..."
npm ci --production=false

log_info "Building Next.js app..."
export NODE_OPTIONS="--max-old-space-size=1536"
npm run build

# Create systemd service
log_info "Creating systemd service..."
cat > /etc/systemd/system/$PROJECT_NAME.service << EOF
[Unit]
Description=Next.js App - $PROJECT_NAME
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=$APP_PORT

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
log_info "Setting permissions..."
chown -R www-data:www-data $PROJECT_DIR
chmod -R 755 $PROJECT_DIR

# Create initial Nginx config (HTTP only for certbot validation)
log_info "Creating initial Nginx configuration..."
cat > $NGINX_AVAILABLE << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    
    location / {
        proxy_pass http://localhost:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \\\$host;
        proxy_cache_bypass \\\$http_upgrade;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \\\$scheme;
    }
}
EOF

# Enable site
ln -sf $NGINX_AVAILABLE $NGINX_ENABLED

# Remove default nginx site if it exists
if [[ -f /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
fi

# Test nginx config
log_info "Testing Nginx configuration..."
nginx -t || log_error "Nginx configuration test failed"

# Restart nginx
log_info "Restarting Nginx..."
systemctl restart nginx

# Start Next.js app
log_info "Starting Next.js application..."
systemctl daemon-reload
systemctl enable $PROJECT_NAME
systemctl start $PROJECT_NAME

# Wait for app to start
log_info "Waiting for application to start..."
sleep 10

# Check if app is running
if systemctl is-active --quiet $PROJECT_NAME; then
    log_info "Next.js app is running successfully"
else
    log_warn "Failed to start Next.js app. Checking logs..."
    journalctl -u $PROJECT_NAME -n 50 --no-pager
    log_error "Application failed to start. Check logs above."
fi

# Test if app responds
log_info "Testing if application responds..."
for i in {1..30}; do
    if curl -s http://localhost:$APP_PORT > /dev/null; then
        log_info "Application is responding on port $APP_PORT"
        break
    fi
    if [[ $i -eq 30 ]]; then
        log_error "Application not responding after 30 seconds"
    fi
    sleep 1
done

# Health check test
log_info "Running health check..."
if curl -f http://localhost:$APP_PORT/api/health > /dev/null 2>&1; then
    log_info "Health check passed"
else
    log_warn "Health check failed, but continuing..."
fi

# Obtain SSL certificate
log_info "Obtaining SSL certificate from Let's Encrypt..."
log_warn "Make sure your domain $DOMAIN points to this server's IP address!"

# Try to get certificate for both root and www
SSL_SUCCESS=false
if certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email $EMAIL --redirect; then
    log_info "SSL certificate obtained successfully for $DOMAIN and www.$DOMAIN"
    SSL_SUCCESS=true
else
    log_warn "Failed to obtain certificate for both domains. Retrying with root domain only..."
    # Fallback: Try root domain only
    if certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL --redirect; then
        log_info "SSL certificate obtained successfully for $DOMAIN (excluding www)"
        SSL_SUCCESS=true
    else
        log_warn "SSL certificate request failed. Site will run on HTTP only."
        log_warn "Please check: 1) DNS points to this server, 2) Port 80/443 are open, 3) Domain is accessible"
        SSL_SUCCESS=false
    fi
fi

if [ "$SSL_SUCCESS" = true ]; then
    # Add log format and rate limiting to main nginx.conf if not already present
    log_info "Configuring Nginx global settings..."
    
    # Check and add analytics log format
    if ! grep -q "log_format analytics_log" /etc/nginx/nginx.conf; then
        log_info "Adding analytics log format to nginx.conf..."
        sed -i '/http {/a \    # Analytics log format\n    log_format analytics_log escape=json '"'"'{\n        "time": "$time_iso8601",\n        "ip": "$remote_addr",\n        "method": "$request_method",\n        "uri": "$request_uri",\n        "status": $status,\n        "bytes_sent": $bytes_sent,\n        "bytes_received": $request_length,\n        "request_time": $request_time,\n        "referer": "$http_referer",\n        "user_agent": "$http_user_agent"\n    }'"'"';\n' /etc/nginx/nginx.conf
    else
        log_info "Analytics log format already configured"
    fi
    
    # Check and add rate limiting zones (check for project-specific zones)
    # Remove old zones for this project first
    sed -i "/zone=${PROJECT_NAME}_api/d" /etc/nginx/nginx.conf
    sed -i "/zone=${PROJECT_NAME}_general/d" /etc/nginx/nginx.conf

    # Now add fresh zones
    log_info "Adding rate limiting zones to nginx.conf..."
    sed -i '/http {/a \    # Rate limiting zones for '"$PROJECT_NAME"'\n    limit_req_zone $binary_remote_addr zone='"${PROJECT_NAME}"'_api:10m rate=10r/s;\n    limit_req_zone $binary_remote_addr zone='"${PROJECT_NAME}"'_general:10m rate=100r/s;\n' /etc/nginx/nginx.conf
    
    # Create secure Nginx configuration
    log_info "Creating secure Nginx configuration..."
    cat > $NGINX_AVAILABLE << 'NGINXEOF'
# Redirect www to non-www (HTTPS)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.DOMAIN_PLACEHOLDER;
    
    ssl_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
    
    return 301 https://DOMAIN_PLACEHOLDER$request_uri;
}

# Main server block
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL_PROJECT_NAME_PLACEHOLDER:50m;
    ssl_session_tickets off;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Logging with analytics format
    access_log /var/log/nginx/DOMAIN_PLACEHOLDER.access.log analytics_log;
    error_log /var/log/nginx/DOMAIN_PLACEHOLDER.error.log;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml font/truetype font/opentype application/vnd.ms-fontobject image/svg+xml;

    # Client body size
    client_max_body_size 10M;

    # Proxy settings
    location / {
        limit_req zone=PROJECT_NAME_PLACEHOLDER_general burst=20 nodelay;
        
        proxy_pass http://localhost:APP_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Next.js static files with long cache
    location /_next/static {
        proxy_pass http://localhost:APP_PORT_PLACEHOLDER;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }

    # API routes with stricter rate limiting
    location /api {
        limit_req zone=PROJECT_NAME_PLACEHOLDER_api burst=5 nodelay;
        
        proxy_pass http://localhost:APP_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Security - block sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(env|log|sql|db)$ {
        deny all;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_PLACEHOLDER www.DOMAIN_PLACEHOLDER;
    return 301 https://DOMAIN_PLACEHOLDER$request_uri;
}
NGINXEOF

    # Replace placeholders
    sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" $NGINX_AVAILABLE
    sed -i "s/APP_PORT_PLACEHOLDER/$APP_PORT/g" $NGINX_AVAILABLE
    sed -i "s/PROJECT_NAME_PLACEHOLDER/$PROJECT_NAME/g" $NGINX_AVAILABLE
    sed -i "s/SSL_PROJECT_NAME_PLACEHOLDER/SSL_${PROJECT_NAME}/g" $NGINX_AVAILABLE

    # Test and reload nginx
    log_info "Testing final Nginx configuration..."
        NGINX_TEST_OUTPUT=$(nginx -t 2>&1)
        if echo "$NGINX_TEST_OUTPUT" | grep -q "conflicts with already declared size"; then
            log_warn "SSL session cache zone name conflict detected. Renaming zone to project-specific name..."
            # Rename the SSL session cache zone to avoid conflicts with other sites
            sed -i "s/ssl_session_cache shared:SSL:/ssl_session_cache shared:SSL_${PROJECT_NAME}:/g" "$NGINX_AVAILABLE"
            log_info "Retrying Nginx configuration test..."
            if nginx -t; then
                log_info "Reloading Nginx with secure configuration..."
                systemctl reload nginx
                log_info "SSL configuration applied successfully"
            else
                log_error "Nginx configuration test failed after SSL setup. Run 'nginx -t' for details."
            fi
        elif nginx -t 2>/dev/null; then
            log_info "Reloading Nginx with secure configuration..."
            systemctl reload nginx
            log_info "SSL configuration applied successfully"
        else
            log_error "Nginx configuration test failed after SSL setup. Run 'nginx -t' for details."
        fi
else
    log_warn "Running on HTTP only due to SSL certificate failure"
fi

# Setup automatic certificate renewal
log_info "Setting up automatic SSL certificate renewal..."
systemctl enable certbot.timer 2>/dev/null || true
systemctl start certbot.timer 2>/dev/null || true

# Create backup script
log_info "Creating backup utility..."
cat > "$PROJECT_DIR/backup.sh" << 'BACKUPEOF'
#!/bin/bash
PROJECT_NAME="PROJECT_NAME_PLACEHOLDER"
DB_TYPE="DB_TYPE_PLACEHOLDER"
BACKUP_DIR="/var/backups/$PROJECT_NAME"

mkdir -p "$BACKUP_DIR"

if [[ "$DB_TYPE" == "mariadb" ]]; then
    DB_USER="DB_USER_PLACEHOLDER"
    DB_PASSWORD="DB_PASSWORD_PLACEHOLDER"
    DB_NAME="DB_NAME_PLACEHOLDER"
    mysqldump -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" | gzip > "$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).sql.gz"
    echo "MariaDB backup created"
else
    if [[ -f "analytics.db" ]]; then
        cp analytics.db "$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).db"
        echo "SQLite backup created"
    fi
fi

# Keep only last 7 backups
ls -t "$BACKUP_DIR"/db_* | tail -n +8 | xargs -r rm
echo "Backup completed. Location: $BACKUP_DIR"
BACKUPEOF

# Replace placeholders in backup script
sed -i "s/PROJECT_NAME_PLACEHOLDER/$PROJECT_NAME/g" "$PROJECT_DIR/backup.sh"
sed -i "s/DB_TYPE_PLACEHOLDER/$DB_TYPE/g" "$PROJECT_DIR/backup.sh"
if [[ "$DB_TYPE" == "mariadb" ]]; then
    sed -i "s/DB_USER_PLACEHOLDER/$DB_USER/g" "$PROJECT_DIR/backup.sh"
    sed -i "s/DB_PASSWORD_PLACEHOLDER/$DB_PASSWORD/g" "$PROJECT_DIR/backup.sh"
    sed -i "s/DB_NAME_PLACEHOLDER/$DB_NAME/g" "$PROJECT_DIR/backup.sh"
fi
chmod +x "$PROJECT_DIR/backup.sh"

# Create credentials file
CREDS_FILE="$PROJECT_DIR/credentials.txt"
cat > $CREDS_FILE << EOF
# Create credentials file
echo "========================================"
echo "SETUP COMPLETE"
echo "========================================"
echo ""
echo "Domain: https://$DOMAIN"
echo "Admin Dashboard: https://$DOMAIN/admin"
echo ""
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASSWORD"
echo ""
echo "Database: $DB_TYPE"
echo ""

if [[ "$DB_TYPE" == "mariadb" ]]; then
    echo "Database Details:"
    echo "  Database Name: $DB_NAME"
    echo "  Database User: $DB_USER"
    echo "  Database Password: $DB_PASSWORD"
    echo "  Database Host: $DB_HOST"
    echo "  Database Port: $DB_PORT"
    echo ""
    echo "MySQL Command Line Access:"
    echo "  mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME"
    echo ""
fi

cat > $CREDS_FILE << EOF
========================================
NEXT.JS APPLICATION CREDENTIALS
========================================

DOMAIN INFORMATION:
  Primary URL: https://$DOMAIN
  Admin Dashboard: https://$DOMAIN/admin
  Info Page: https://$DOMAIN/info

ADMIN CREDENTIALS:
  Username: $ADMIN_USER
  Password: $ADMIN_PASSWORD

DATABASE INFORMATION:
  Type: $DB_TYPE
EOF

if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
  Database Name: $DB_NAME
  Database User: $DB_USER
  Database Password: $DB_PASSWORD
  Database Host: $DB_HOST
  Database Port: $DB_PORT
 
  MySQL CLI Access:
    mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME
 
  MySQL Root Access:
    sudo mysql
 
  Create Database Backup:
    mysqldump -u $DB_USER -p'$DB_PASSWORD' $DB_NAME > backup.sql
EOF
else
    cat >> $CREDS_FILE << EOF
  Database File: $PROJECT_DIR/analytics.db
 
  SQLite CLI Access:
    sqlite3 $PROJECT_DIR/analytics.db
EOF
fi

cat >> $CREDS_FILE << EOF

APPLICATION DETAILS:
  Project Name: $PROJECT_NAME
  Project Directory: $PROJECT_DIR
  Service Name: $PROJECT_NAME
  Application Port: $APP_PORT
  Node Environment: production

API ENDPOINTS:
  Health Check:
    GET https://$DOMAIN/api/health
 
  Example Endpoints:
    GET  https://$DOMAIN/api/example
    POST https://$DOMAIN/api/example
 
  Authentication:
    POST https://$DOMAIN/api/auth/login
    Body: {"username": "$ADMIN_USER", "password": "$ADMIN_PASSWORD"}
 
  Analytics (requires auth token):
    GET https://$DOMAIN/api/analytics/summary?days=7
    GET https://$DOMAIN/api/analytics/detailed?days=7&page=1&limit=50
    GET https://$DOMAIN/api/analytics/traffic?days=7

SYSTEM COMMANDS:
  View Application Logs:
    journalctl -u $PROJECT_NAME -f
    journalctl -u $PROJECT_NAME -n 100 --no-pager
 
  Restart Application:
    sudo systemctl restart $PROJECT_NAME
 
  Stop Application:
    sudo systemctl stop $PROJECT_NAME
 
  Start Application:
    sudo systemctl start $PROJECT_NAME
 
  Check Application Status:
    sudo systemctl status $PROJECT_NAME
 
  View Nginx Access Logs:
    tail -f /var/log/nginx/$DOMAIN.access.log
 
  View Nginx Error Logs:
    tail -f /var/log/nginx/$DOMAIN.error.log
 
  Test Nginx Configuration:
    sudo nginx -t
 
  Reload Nginx:
    sudo systemctl reload nginx
 
  SSL Certificate Management:
    certbot certificates
    certbot renew --dry-run
    certbot renew
 
  Create Database Backup:
    $PROJECT_DIR/backup.sh
 
  View Backups:
    ls -lh /var/backups/$PROJECT_NAME/

SECURITY FEATURES:
  ✓ TLS 1.2/1.3 with strong ciphers
  ✓ HSTS with preload
  ✓ Security headers (X-Frame-Options, CSP, X-Content-Type-Options)
  ✓ OCSP stapling
  ✓ Automatic SSL certificate renewal (certbot.timer)
  ✓ Request/response analytics tracking
  ✓ Bandwidth monitoring
  ✓ JWT-based admin authentication (7-day token expiry)
  ✓ Password hashing with bcrypt (12 rounds)
  ✓ Rate limiting:
      - API endpoints: 10 requests/second (burst: 5)
      - General pages: 100 requests/second (burst: 20)
  ✓ Gzip compression enabled
  ✓ Health check endpoint
  ✓ Automated backup script
  ✓ Environment variable protection (.env not in git)

FILE LOCATIONS:
  Project Root: $PROJECT_DIR
  Environment Config: $PROJECT_DIR/.env
  Database Schema: $PROJECT_DIR/prisma/schema.prisma
  Nginx Config: /etc/nginx/sites-available/$DOMAIN
  SSL Certificates: /etc/letsencrypt/live/$DOMAIN/
  Systemd Service: /etc/systemd/system/$PROJECT_NAME.service
  Backup Script: $PROJECT_DIR/backup.sh
  Backups Directory: /var/backups/$PROJECT_NAME/
  This File: $CREDS_FILE

TESTING COMMANDS:
  Test Homepage:
    curl -I https://$DOMAIN
 
  Test Health Endpoint:
    curl https://$DOMAIN/api/health
 
  Test API Endpoint:
    curl https://$DOMAIN/api/example
 
  Test Admin Login:
    curl -X POST https://$DOMAIN/api/auth/login \\
      -H "Content-Type: application/json" \\
      -d '{"username":"$ADMIN_USER","password":"$ADMIN_PASSWORD"}'
 
  Test Analytics (replace TOKEN):
    curl https://$DOMAIN/api/analytics/summary?days=7 \\
      -H "Authorization: Bearer TOKEN"

TROUBLESHOOTING:
  Application won't start:
    - Check logs: journalctl -u $PROJECT_NAME -n 50
    - Check port: lsof -i :$APP_PORT
    - Check permissions: ls -la $PROJECT_DIR
 
  Database connection issues:
EOF

if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
    - Test connection: mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME -e "SELECT 1;"
    - Check MariaDB status: systemctl status mariadb
    - View MariaDB logs: journalctl -u mariadb -n 50
EOF
else
    cat >> $CREDS_FILE << EOF
    - Check file exists: ls -la $PROJECT_DIR/analytics.db
    - Check permissions: ls -la $PROJECT_DIR/analytics.db
EOF
fi

cat >> $CREDS_FILE << EOF
 
  SSL certificate issues:
    - Verify DNS: dig $DOMAIN
    - Check firewall: ufw status
    - Manual renewal: certbot renew --force-renewal
 
  Nginx issues:
    - Test config: nginx -t
    - Check syntax: nginx -T
    - View error log: tail -f /var/log/nginx/error.log

MAINTENANCE TASKS:
  Daily:
    - Monitor logs: journalctl -u $PROJECT_NAME --since today
 
  Weekly:
    - Run backup: $PROJECT_DIR/backup.sh
    - Check disk space: df -h
    - Review analytics: https://$DOMAIN/admin
 
  Monthly:
    - Update packages: apt update && apt upgrade
    - Clean old logs: journalctl --vacuum-time=30d
    - Review SSL cert expiry: certbot certificates

IMPORTANT NOTES:
  ⚠ SAVE THIS FILE SECURELY - It contains sensitive credentials
  ⚠ The .env file contains secrets - never commit it to git
  ⚠ Admin password is auto-generated - change it from the dashboard
  ⚠ Database backups are kept for 7 days only
  ⚠ SSL certificates auto-renew via certbot.timer

========================================
Setup completed: $(date)
========================================
EOF

chmod 600 $CREDS_FILE

# Display final status
echo ""
echo "=========================================="
log_info "🎉 Setup completed successfully!"
echo "=========================================="
echo ""
cat $CREDS_FILE
echo ""
echo "📄 Full credentials saved to: $CREDS_FILE"
echo ""

if [[ "$AUTO_GENERATED_PASS" == true ]]; then
    log_warn "⚠️  Admin password was auto-generated. Please save it securely!"
fi

if [ "$SSL_SUCCESS" = true ]; then
    echo "🌐 Your Next.js app is now live at: https://$DOMAIN"
    echo "🔐 SSL certificate installed and configured"
else
    echo "🌐 Your Next.js app is running at: http://$DOMAIN"
    log_warn "SSL setup failed. You can manually configure it later with: certbot --nginx -d $DOMAIN"
fi

echo ""
echo "=========================================="
log_info "📋 Quick Start:"
echo "  1. Visit: https://$DOMAIN"
echo "  2. Admin: https://$DOMAIN/admin"
echo "  3. Login: $ADMIN_USER / $ADMIN_PASSWORD"
echo "  4. Test: curl https://$DOMAIN/api/health"
echo "=========================================="
echo ""
log_info "📚 Post-installation recommendations:"
echo "  1. Run a backup: $PROJECT_DIR/backup.sh"
echo "  2. Check health: curl https://$DOMAIN/api/health"
echo "  3. Monitor logs: journalctl -u $PROJECT_NAME -f"
echo "  4. Review credentials: cat $CREDS_FILE"
echo "=========================================="


if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
  Database: $DB_NAME
  User: $DB_USER
  Password: $DB_PASSWORD
  Host: $DB_HOST
  Port: $DB_PORT
  Connection: mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME
EOF
else
    cat >> $CREDS_FILE << EOF
  Database File: $PROJECT_DIR/analytics.db
EOF
fi

cat >> $CREDS_FILE << EOF

Project Directory: $PROJECT_DIR
Service Name: $PROJECT_NAME
Application Port: $APP_PORT

API Endpoints:
  - GET  /api/health - Health check endpoint
  - GET  /api/example - Example API endpoint
  - POST /api/example - Example POST endpoint
  - POST /api/auth/login - Admin login
  - GET  /api/analytics/summary - Analytics summary
  - GET  /api/analytics/detailed - Detailed analytics
  - GET  /api/analytics/traffic - Traffic stats

Useful Commands:
  - View app logs: journalctl -u $PROJECT_NAME -f
  - Restart app: systemctl restart $PROJECT_NAME
  - Check status: systemctl status $PROJECT_NAME
  - Nginx logs: tail -f /var/log/nginx/$DOMAIN.access.log
  - SSL test: certbot certificates
  - Renew SSL: certbot renew
  - Create backup: $PROJECT_DIR/backup.sh
EOF

if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
  - Database console: mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME
EOF
fi

cat >> $CREDS_FILE << EOF

Security Features Enabled:
  ✓ TLS 1.2/1.3 with strong ciphers
  ✓ HSTS with preload
  ✓ Security headers (X-Frame-Options, CSP, etc.)
  ✓ OCSP stapling
  ✓ Automatic certificate renewal
  ✓ Request/response analytics tracking
  ✓ Bandwidth monitoring
  ✓ JWT-based admin authentication
  ✓ Rate limiting (API: 10req/s, General: 100req/s)
  ✓ Gzip compression
  ✓ Health check endpoint
  ✓ Automated backup script

========================================
IMPORTANT: Save these credentials securely!
========================================
EOF

chmod 600 $CREDS_FILE

# Display final status
echo ""
echo "=========================================="
log_info "🎉 Setup completed successfully!"
echo "=========================================="
echo ""
cat $CREDS_FILE
echo ""
echo "Credentials saved to: $CREDS_FILE"
echo ""

if [[ "$AUTO_GENERATED_PASS" == true ]]; then
    log_warn "Admin password was auto-generated. Please save it securely!"
fi

if [ "$SSL_SUCCESS" = true ]; then
    echo "Your Next.js app is now live at: https://$DOMAIN"
else
    echo "Your Next.js app is running at: http://$DOMAIN"
    log_warn "SSL setup failed. You can manually configure it later with: certbot --nginx -d $DOMAIN"
fi

echo "=========================================="
log_info "Post-installation recommendations:"
echo "  1. Run a backup: $PROJECT_DIR/backup.sh"
echo "  2. Test your site: curl -I https://$DOMAIN"
echo "  3. Check health: curl https://$DOMAIN/api/health"
echo "  4. Monitor logs: journalctl -u $PROJECT_NAME -f"
echo "=========================================="