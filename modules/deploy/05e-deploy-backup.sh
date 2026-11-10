#!/bin/bash

log_info "Setting up automatic SSL certificate renewal..."
systemctl enable certbot.timer 2>/dev/null || true
systemctl start certbot.timer 2>/dev/null || true

log_info "Creating backup utility..."
cat > "$PROJECT_DIR/backup.sh" << 'BACKUPEOF'
#!/bin/bash
set -e
PROJECT_NAME="PROJECT_NAME_PLACEHOLDER"
PROJECT_DIR="/var/www/$PROJECT_NAME"
DB_TYPE="DB_TYPE_PLACEHOLDER"
BACKUP_DIR="/var/backups/$PROJECT_NAME"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

if [[ "$DB_TYPE" == "mariadb" ]]; then
    DB_USER="DB_USER_PLACEHOLDER"
    DB_PASSWORD="DB_PASSWORD_PLACEHOLDER"
    DB_NAME="DB_NAME_PLACEHOLDER"
    DUMP_FILE="$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).sql.gz"
    mysqldump --single-transaction -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" | gzip > "$DUMP_FILE"
    chmod 600 "$DUMP_FILE"
    echo "MariaDB backup created: $DUMP_FILE"
else
    SQLITE_FILE="$PROJECT_DIR/prisma/analytics.db"
    if [[ -f "$SQLITE_FILE" ]]; then
        DUMP_FILE="$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).db"
        if command -v sqlite3 &> /dev/null; then
            sqlite3 "$SQLITE_FILE" ".backup '$DUMP_FILE'"
        else
            cp "$SQLITE_FILE" "$DUMP_FILE"
        fi
        chmod 600 "$DUMP_FILE"
        echo "SQLite backup created: $DUMP_FILE"
    else
        echo "SQLite database file not found at $SQLITE_FILE" >&2
        exit 1
    fi
fi

ls -t "$BACKUP_DIR"/db_* 2>/dev/null | tail -n +8 | xargs -r rm -f
echo "Backup completed. Location: $BACKUP_DIR"
BACKUPEOF

sed -i "s|PROJECT_NAME_PLACEHOLDER|$PROJECT_NAME|g" "$PROJECT_DIR/backup.sh"
sed -i "s|DB_TYPE_PLACEHOLDER|$DB_TYPE|g" "$PROJECT_DIR/backup.sh"

if [[ "$DB_TYPE" == "mariadb" ]]; then
    sed -i "s|DB_USER_PLACEHOLDER|$DB_USER|g" "$PROJECT_DIR/backup.sh"
    sed -i "s|DB_PASSWORD_PLACEHOLDER|$DB_PASSWORD|g" "$PROJECT_DIR/backup.sh"
    sed -i "s|DB_NAME_PLACEHOLDER|$DB_NAME|g" "$PROJECT_DIR/backup.sh"
fi

chmod 700 "$PROJECT_DIR/backup.sh"