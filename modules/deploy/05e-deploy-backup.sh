#!/bin/bash

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
# Dumps contain full DB contents (including hashed passwords, PII) - owner-only.
chmod 700 "$BACKUP_DIR"

if [[ "$DB_TYPE" == "mariadb" ]]; then
    DB_USER="DB_USER_PLACEHOLDER"
    DB_PASSWORD="DB_PASSWORD_PLACEHOLDER"
    DB_NAME="DB_NAME_PLACEHOLDER"
    DUMP_FILE="$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).sql.gz"
    mysqldump -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" | gzip > "$DUMP_FILE"
    chmod 600 "$DUMP_FILE"
    echo "MariaDB backup created"
else
    if [[ -f "analytics.db" ]]; then
        DUMP_FILE="$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).db"
        cp analytics.db "$DUMP_FILE"
        chmod 600 "$DUMP_FILE"
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
# backup.sh has the DB password embedded as plaintext (see sed replacements
# above) — restrict to owner-only, not just executable-for-all.
chmod 700 "$PROJECT_DIR/backup.sh"