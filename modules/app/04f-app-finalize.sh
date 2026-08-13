# =============================================================================
# 04f-app-finalize.sh
# Template copy to homepage, layout.tsx update, next.config.ts, Prisma migration
# Sourced by 04-app.sh — expects TEMPLATE_PATH, log_info() defined. Must run
# last: depends on app/layout.tsx existing (04a) and lib/db.ts existing (04b).
# =============================================================================

# Copy selected template to homepage
log_info "Copying template to homepage..."
cp "$TEMPLATE_PATH" app/page.tsx

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
npx prisma db push --accept-data-loss