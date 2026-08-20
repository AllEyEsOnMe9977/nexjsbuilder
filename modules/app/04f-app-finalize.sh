# =============================================================================
# 04f-app-finalize.sh
# Template copy to homepage, layout.tsx update, next.config.ts, Prisma migration
# Sourced by 04-app.sh — expects TEMPLATE_PATH, log_info() defined. Must run
# last: depends on app/layout.tsx existing (04a) and lib/db.ts existing (04b).
# =============================================================================

# Copy selected template to homepage
log_info "Copying template to homepage..."
log_info "Applying template: $TEMPLATE_PATH"

# page.tsx is mandatory for every template
if [[ ! -f "$TEMPLATE_PATH/page.tsx" ]]; then
    log_info "ERROR: Template missing required page.tsx at $TEMPLATE_PATH"
    exit 1
fi
cp "$TEMPLATE_PATH/page.tsx" app/page.tsx

# Optional template components (merged into project components/)
if [[ -d "$TEMPLATE_PATH/components" ]]; then
    log_info "Copying template components..."
    cp -r "$TEMPLATE_PATH/components/." components/
fi

# Optional template API routes (merged into app/api/)
if [[ -d "$TEMPLATE_PATH/api" ]]; then
    log_info "Copying template API routes..."
    mkdir -p app/api
    cp -r "$TEMPLATE_PATH/api/." app/api/
fi

# Optional nested app routes (e.g. app/product/[id]/page.tsx, app/cart/page.tsx)
# Template ships these under templates/<name>/routes/ mirroring the app/ tree,
# excluding the homepage (already handled above via page.tsx) and api/ (handled above).
if [[ -d "$TEMPLATE_PATH/routes" ]]; then
    log_info "Copying template nested routes..."
    cp -r "$TEMPLATE_PATH/routes/." app/
fi

# Optional template-specific env vars, appended to .env
if [[ -f "$TEMPLATE_PATH/.env.template" ]]; then
    log_info "Appending template environment variables..."
    cat "$TEMPLATE_PATH/.env.template" >> .env
fi

# Update layout to include ClientAnalytics
log_info "Updating layout with analytics..."
if [[ -f "app/layout.tsx" ]]; then
    # Add import if not present
    if ! grep -q "ClientAnalytics" app/layout.tsx; then
        sed -i '/import.*globals\.css/a import { ClientAnalytics } from "@/components/ClientAnalytics";' app/layout.tsx
        sed -i 's/<body\(.*\)>/<body\1>\n        <ClientAnalytics \/>/' app/layout.tsx
    fi
fi

# Update next.config
cat > next.config.ts << 'EOF'
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
};

export default nextConfig;
EOF

# Run Prisma migrations
log_info "Running database migrations..."
npx prisma generate

# The app DB user only has SELECT/INSERT/UPDATE/DELETE (see 03-system.sh) so
# it can't create/alter tables. Grant DDL rights just for this push, then
# revoke back down immediately - the running app never needs schema control.
if [[ "$DB_TYPE" == "mariadb" ]]; then
    mysql -e "GRANT CREATE, ALTER, DROP, INDEX, REFERENCES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
fi

npx prisma db push --accept-data-loss

if [[ "$DB_TYPE" == "mariadb" ]]; then
    mysql -e "REVOKE CREATE, ALTER, DROP, INDEX, REFERENCES ON $DB_NAME.* FROM '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    log_info "DDL privileges revoked - app DB user restricted to CRUD only."
fi