# =============================================================================
# 04-app.sh
# Orchestrator: sources the split app-build modules in dependency order.
# Split from the original monolithic 04-app.sh for maintainability.
# All modules must sit alongside this file in the same "modules" directory.
# =============================================================================

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/app" && pwd)"

log_info "Starting application build (04-app.sh)..."

source "$MODULE_DIR/04a-app-init.sh"          # Project scaffold, deps, Prisma schema
source "$MODULE_DIR/04b-app-env.sh"           # .env, lib/db.ts, lib/auth.ts, lib/analytics.ts
source "$MODULE_DIR/04c-app-middleware.sh"    # Analytics record endpoint + middleware.ts
source "$MODULE_DIR/04d-app-api.sh"           # All app/api/* routes
source "$MODULE_DIR/04e-app-components.sh"    # ClientAnalytics, admin dashboard, info page
source "$MODULE_DIR/04f-app-finalize.sh"      # Homepage template, layout.tsx, next.config, migrate

log_info "Application build complete (04-app.sh)."