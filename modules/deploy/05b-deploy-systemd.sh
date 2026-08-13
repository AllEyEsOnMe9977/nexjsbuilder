#!/bin/bash

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