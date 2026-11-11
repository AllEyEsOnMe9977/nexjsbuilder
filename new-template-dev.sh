#!/bin/bash
# =============================================================================
# new-template-dev.sh
# Scaffolds a standalone dev project that mirrors the builder's base app
# (same create-next-app flags, Prisma 5 + SQLite, lib/db.ts, lib/utils.ts,
# components.json, next.config.ts). Develop your template here, then convert it
# with ./import-template.sh <this-dir> <category>/<variant>.
#
# Usage:  ./new-template-dev.sh <target-dir>
# Env:    NO_INSTALL=1  -> generate files only, skip npm installs (for testing)
# Does NOT need root.
# =============================================================================

set -euo pipefail

# --- Minimal logging (01-utils.sh cannot be sourced here: it requires root) ---
log_info()  { echo "[INFO]  $1"; }
log_warn()  { echo "[WARN]  $1" >&2; }
log_error() { echo "[ERROR] $1" >&2; exit 1; }

TARGET="${1:-}"
[[ -n "$TARGET" ]] || log_error "Usage: $0 <target-dir>"
[[ ! -e "$TARGET" ]] || log_error "Target already exists: $TARGET"

export NEXT_TELEMETRY_DISABLED=1
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd)"
cd "$TARGET"

# --- 1. Same scaffold flags as 04a-app-init.sh --------------------------------
log_info "Creating Next.js app (same flags as the builder)..."
CNA_EXTRA=()
[[ "${NO_INSTALL:-0}" == "1" ]] && CNA_EXTRA+=(--skip-install)
npx --yes create-next-app@latest . --typescript --tailwind --app --no-src-dir \
    --import-alias "@/*" --use-npm --yes "${CNA_EXTRA[@]}"

# --- 2. components.json identical to the builder's ----------------------------
log_info "Writing components.json..."
cat > components.json << 'EOF'
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "base-nova",
  "rsc": true,
  "tsx": true,
  "tailwind": {
    "config": "",
    "css": "app/globals.css",
    "baseColor": "neutral",
    "cssVariables": true,
    "prefix": ""
  },
  "iconLibrary": "lucide",
  "rtl": false,
  "aliases": {
    "components": "@/components",
    "utils": "@/lib/utils",
    "ui": "@/components/ui",
    "lib": "@/lib",
    "hooks": "@/hooks"
  },
  "menuColor": "default",
  "menuAccent": "subtle",
  "registries": {
    "@magicui": "https://magicui.design/r/{name}"
  }
}
EOF

# --- 3. Base dependencies the builder installs (do NOT list these in manifest) -
if [[ "${NO_INSTALL:-0}" != "1" ]]; then
    log_info "Installing builder base dependencies..."
    npm install @prisma/client@5 bcryptjs jsonwebtoken clsx tailwind-merge
    npm install -D prisma@5 @types/bcryptjs @types/jsonwebtoken
else
    log_warn "NO_INSTALL=1 - skipping npm installs."
fi

# --- 4. lib/ files identical to 04b-app-env.sh --------------------------------
log_info "Writing lib/utils.ts and lib/db.ts (identical to builder)..."
mkdir -p lib
cat > lib/utils.ts << 'EOF'
import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
EOF

cat > lib/db.ts << 'EOF'
import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

export const prisma = globalForPrisma.prisma ?? new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['error', 'warn'] : ['error'],
})

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma

export default prisma
EOF

# --- 5. Prisma schema: builder base models + a marked area for YOUR models -----
log_info "Writing prisma/schema.prisma..."
mkdir -p prisma
cat > prisma/schema.prisma << 'EOF'
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite"
  url      = env("DATABASE_URL")
}

// ===== BUILDER BASE MODELS - keep identical, never edit (import skips them) =====
model User {
  id        String   @id @default(cuid())
  username  String   @unique
  password  String
  role      String   @default("admin")
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model Analytics {
  id            String   @id @default(cuid())
  timestamp     DateTime @default(now())
  ip            String
  userAgent     String?
  method        String
  path          String
  statusCode    Int
  responseTime  Int
  referer       String?
  country       String?
  city          String?
  device        String?
  browser       String?
  os            String?
  bytesIn       Int      @default(0)
  bytesOut      Int      @default(0)

  @@index([timestamp])
  @@index([ip])
  @@index([path])
}

model ApiStats {
  id           String   @id @default(cuid())
  timestamp    DateTime @default(now())
  endpoint     String
  method       String
  statusCode   Int
  responseTime Int

  @@index([timestamp])
  @@index([endpoint])
}
// ===== END BUILDER BASE MODELS =====

// ===== YOUR TEMPLATE MODELS BELOW =====
// Rules: no enums, no Json, no scalar lists (String[]), no @db.* attributes,
// and do not reference User. The builder supports SQLite AND MariaDB with Prisma 5.
EOF

# --- 6. Env files --------------------------------------------------------------
# Only .env.example is imported; builder-owned vars are stripped on import.
log_info "Writing .env and .env.example..."
echo 'DATABASE_URL="file:./dev.db"' > .env
cat > .env.example << 'EOF'
# Template-specific variables ONLY. The builder already sets DATABASE_URL,
# JWT_SECRET, ADMIN_USERNAME, NEXT_PUBLIC_SITE_URL, NODE_ENV and PORT.
# Example:
# SHOP_CURRENCY=USD
EOF

# --- 7. next.config.ts identical to 04f-app-finalize.sh ------------------------
log_info "Writing next.config.ts (identical to builder output)..."
cat > next.config.ts << 'EOF'
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
EOF

# --- 8. npm scripts: one-command pre-import check ------------------------------
if [[ -f package.json ]]; then
    node -e '
      const fs = require("fs");
      const p = JSON.parse(fs.readFileSync("package.json", "utf8"));
      p.scripts = p.scripts || {};
      p.scripts["db:push"] = "prisma db push --accept-data-loss";
      p.scripts["template:check"] = "prisma generate && prisma db push --accept-data-loss && tsc --noEmit && next build";
      fs.writeFileSync("package.json", JSON.stringify(p, null, 2) + "\n");
    '
    log_info "Added npm scripts: db:push, template:check"
fi

# --- 9. Rules file that travels with the project --------------------------------
cat > TEMPLATE_RULES.md << 'EOF'
# Template rules (so import into the builder never breaks)

1. Homepage is `app/page.tsx`. Pages that read the DB must export `dynamic = "force-dynamic"`.
2. Never create/edit: `lib/db.ts`, `lib/auth.ts`, `lib/analytics.ts`, `lib/utils.ts`,
   `components/ClientAnalytics.tsx`, `proxy.ts`/`middleware.ts`, `next.config.ts`.
3. Never use these paths: `app/admin`, `app/info`, `app/api/auth`, `app/api/analytics`,
   `app/api/health`, `app/api/example`.
4. Prisma: no enums, no Json, no scalar lists, no `@db.*`, no relations to `User`.
   Do not edit the builder base models.
5. Import only through the `@/` alias (e.g. `@/lib/db`, `@/components/X`). No relative `../../`.
6. Extra npm packages: install normally; they are exported to manifest.json on import.
   Do not install anything the builder already provides (see `package.json` base list).
7. Template env vars go in `.env.example` only. Read them with `process.env.X` and
   always provide a safe fallback. Never commit secrets.
8. The first visit has an EMPTY database: every page must render without rows.
9. Put images in `public/`. No remote-only assets required to render.
10. Before importing, run `npm run template:check` - it must pass.

P.S:
Work ONLY inside the provided Next.js project (it already has app/, lib/, prisma/).
Do NOT create a new project. Do NOT use Vite, Express, or any non-Next.js tooling.
Do NOT edit package.json by hand; add packages only with `npm install <pkg>`.
Do NOT touch lib/db.ts, lib/utils.ts, next.config.ts, or the builder base models in prisma/schema.prisma.
Build pages with the Next.js App Router in app/. Put server logic in app/api/**/route.ts, not Express.
Components that use hooks or browser APIs need "use client" at the top.
Finish by running `npm run template:check` and fix every error until it passes.
EOF

log_info "Dev project ready at $TARGET"
log_info "Next: cd $TARGET && npm run dev   (develop), npm run template:check (verify)"
log_info "Import: ./import-template.sh $TARGET <category>/<variant>"