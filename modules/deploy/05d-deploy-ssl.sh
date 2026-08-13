#!/bin/bash

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