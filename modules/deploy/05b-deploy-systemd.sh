#!/bin/bash

log_info "Creating systemd service..."
cat > "/etc/systemd/system/$PROJECT_NAME.service" << EOF
[Unit]
Description=Next.js App - $PROJECT_NAME
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/node_modules/.bin/next start -p $APP_PORT
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=$APP_PORT

[Install]
WantedBy=multi-user.target
EOF

log_info "Setting permissions..."
chown -R www-data:www-data "$PROJECT_DIR"
chmod -R 755 "$PROJECT_DIR"

log_info "Re-securing .env permissions..."
chmod 600 "$PROJECT_DIR/.env"