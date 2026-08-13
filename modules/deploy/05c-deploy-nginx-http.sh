#!/bin/bash

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