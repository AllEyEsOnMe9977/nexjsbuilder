#!/bin/bash

# Create credentials file
CREDS_FILE="$PROJECT_DIR/credentials.txt"
log_info "Generating comprehensive credentials file..."

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