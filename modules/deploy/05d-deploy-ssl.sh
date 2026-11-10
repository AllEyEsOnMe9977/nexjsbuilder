#!/bin/bash

log_info "Obtaining SSL certificate from Let's Encrypt..."
log_warn "Make sure your domain $DOMAIN points to this server's IP address!"

SSL_SUCCESS=false
SSL_HAS_WWW=false
ZONE_PREFIX="${PROJECT_NAME//-/_}"

if certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "$EMAIL" --redirect; then
    log_info "SSL certificate obtained successfully for $DOMAIN and www.$DOMAIN"
    SSL_SUCCESS=true
    SSL_HAS_WWW=true
else
    log_warn "Failed to obtain certificate for both domains. Retrying with $DOMAIN only..."
    if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "$EMAIL" --redirect; then
        log_info "SSL certificate obtained successfully for $DOMAIN (excluding www)"
        SSL_SUCCESS=true
        SSL_HAS_WWW=false
    else
        log_warn "SSL certificate request failed. Site will run on HTTP only."
        SSL_SUCCESS=false
    fi
fi

if [ "$SSL_SUCCESS" = true ]; then
    log_info "Configuring Nginx global settings..."

    if ! grep -q "log_format analytics_log" /etc/nginx/nginx.conf; then
        sed -i '/http {/a \    log_format analytics_log escape=json '"'"'{"time":"$time_iso8601","ip":"$remote_addr","method":"$request_method","uri":"$request_uri","status":$status,"bytes_sent":$bytes_sent,"bytes_received":$request_length,"request_time":$request_time,"referer":"$http_referer","user_agent":"$http_user_agent"}'"'"';' /etc/nginx/nginx.conf
    fi

    sed -i "/# Rate limiting zones for ${PROJECT_NAME}/d" /etc/nginx/nginx.conf
    sed -i "/zone=${ZONE_PREFIX}_api/d" /etc/nginx/nginx.conf
    sed -i "/zone=${ZONE_PREFIX}_general/d" /etc/nginx/nginx.conf

    sed -i '/http {/a \    # Rate limiting zones for '"$PROJECT_NAME"'\n    limit_req_zone $binary_remote_addr zone='"${ZONE_PREFIX}"'_api:10m rate=10r/s;\n    limit_req_zone $binary_remote_addr zone='"${ZONE_PREFIX}"'_general:10m rate=100r/s;' /etc/nginx/nginx.conf

    > "$NGINX_AVAILABLE"

    if [ "$SSL_HAS_WWW" = true ]; then
        cat >> "$NGINX_AVAILABLE" << EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.$DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    return 301 https://$DOMAIN\$request_uri;
}
EOF
    fi

    cat >> "$NGINX_AVAILABLE" << EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL_${ZONE_PREFIX}:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    access_log /var/log/nginx/$DOMAIN.access.log analytics_log;
    error_log /var/log/nginx/$DOMAIN.error.log;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml image/svg+xml;

    client_max_body_size 10M;

    location / {
        limit_req zone=${ZONE_PREFIX}_general burst=20 nodelay;
        proxy_pass http://localhost:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location ^~ /_next/static {
        proxy_pass http://localhost:$APP_PORT;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    location ^~ /api {
        limit_req zone=${ZONE_PREFIX}_api burst=5 nodelay;
        proxy_pass http://localhost:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location ~ /\. {
        deny all;
    }

    location ~ \.(env|log|sql|db)$ {
        deny all;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN $([ "$SSL_HAS_WWW" = true ] && echo "www.$DOMAIN");
    return 301 https://$DOMAIN\$request_uri;
}
EOF

    log_info "Testing final Nginx configuration..."
    if nginx -t; then
        systemctl reload nginx
        log_info "SSL configuration applied successfully"
    else
        log_error "Nginx configuration test failed after SSL setup."
    fi
else
    log_warn "Running on HTTP only due to SSL certificate failure"
fi