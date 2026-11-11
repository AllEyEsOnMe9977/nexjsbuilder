#!/bin/bash
# =============================================================================
# import-template.sh
# Converts a standalone Next.js project into a builder template under
# templates/<name>/ so it shows up in the setup.sh template menu.
#
# Usage:  ./import-template.sh <path-to-standalone-project> <category>/<variant> [--force]
# Example: ./import-template.sh ~/my-shop shop/modern   (category alone => variant "default")
#
# Does NOT need root. Never copies .env files (secrets) - only .env.example.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Minimal logging (01-utils.sh cannot be sourced here: it requires root) ---
log_info()  { echo "[INFO]  $1"; }
log_warn()  { echo "[WARN]  $1" >&2; }
log_error() { echo "[ERROR] $1" >&2; exit 1; }

# --- Arguments ---------------------------------------------------------------
SRC="${1:-}"
RAW_NAME="${2:-}"
FORCE="${3:-}"

[[ -n "$SRC" && -n "$RAW_NAME" ]] || log_error "Usage: $0 <project-path> <category>/<variant> [--force]"
[[ -d "$SRC" ]] || log_error "Source directory not found: $SRC"
SRC="$(cd "$SRC" && pwd)"

# Name format: <category>/<variant>  (category alone => variant "default")
[[ "$RAW_NAME" =~ ^[^/]+(/[^/]+)?$ ]] || log_error "Template name must be <category> or <category>/<variant>, got: $RAW_NAME"

# Same sanitizing rules as sanitize_project_name() in 01-utils.sh, applied per part
sanitize_part() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | tr '_' '-' | tr ' ' '-' | sed 's/[^a-z0-9-]//g; s/^-*//; s/-*$//'
}
IFS='/' read -r RAW_CAT RAW_VAR <<< "$RAW_NAME"
CATEGORY="$(sanitize_part "$RAW_CAT")"
VARIANT="$(sanitize_part "${RAW_VAR:-default}")"
[[ -n "$CATEGORY" && -n "$VARIANT" ]] || log_error "Invalid template name: $RAW_NAME"
NAME="$CATEGORY/$VARIANT"

# A flat template (page.tsx directly inside the category) would hide its variants
if [[ -f "$SCRIPT_DIR/templates/$CATEGORY/page.tsx" ]]; then
    log_error "templates/$CATEGORY is a flat template. Move its files into templates/$CATEGORY/default/ first."
fi

DEST="$SCRIPT_DIR/templates/$NAME"
if [[ -e "$DEST" ]]; then
    [[ "$FORCE" == "--force" ]] || log_error "Template '$NAME' already exists. Re-run with --force to overwrite."
    log_warn "Overwriting existing template: $DEST"
    rm -rf "$DEST"
fi

# --- Guard: refuse non-Next.js projects (Vite, CRA, Express...) before copying anything ---
if [[ -f "$SRC/package.json" ]]; then
    if ! node "$SCRIPT_DIR/check-packages.js" "$SCRIPT_DIR/blocked-packages.txt" "$SRC/package.json" --require-next; then
        log_error "Source project is not a valid Next.js template source. Nothing was imported."
    fi
else
    log_warn "No package.json in source - cannot verify the stack."
fi

# --- Locate the app root (supports both ./app and ./src/app layouts) ---------
if   [[ -d "$SRC/src/app" ]]; then ROOT="$SRC/src"
elif [[ -d "$SRC/app"     ]]; then ROOT="$SRC"
else log_error "No app/ directory found in $SRC (App Router projects only)."
fi
APP="$ROOT/app"

# The builder requires a homepage
PAGE=""
for ext in tsx jsx; do [[ -f "$APP/page.$ext" ]] && PAGE="$APP/page.$ext" && break; done
[[ -n "$PAGE" ]] || log_error "Missing app/page.tsx - every template needs a homepage."
[[ "$PAGE" == *.tsx ]] || log_warn "Homepage is .jsx; it will be copied as page.tsx. Verify it compiles."

# Paths the builder itself generates - template files must not collide with these
RESERVED_ROUTES=("admin" "info")
RESERVED_API=("auth" "analytics" "health" "example")
RESERVED_LIB=("db.ts" "auth.ts" "analytics.ts" "utils.ts")

in_list() { local n="$1"; shift; local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }

mkdir -p "$DEST"
log_info "Importing '$SRC' -> '$DEST'"

# --- 1. Homepage -------------------------------------------------------------
cp "$PAGE" "$DEST/page.tsx"
log_info "Homepage copied."

# --- 2. Optional custom layout (fonts, metadata); builder re-injects analytics ---
for ext in tsx jsx; do
    if [[ -f "$APP/layout.$ext" ]]; then
        cp "$APP/layout.$ext" "$DEST/layout.tsx"
        log_info "Custom layout copied."
        break
    fi
done

# --- 3. API routes -> api/ ---------------------------------------------------
if [[ -d "$APP/api" ]]; then
    mkdir -p "$DEST/api"
    for entry in "$APP/api"/*; do
        [[ -e "$entry" ]] || continue
        base="$(basename "$entry")"
        if in_list "$base" "${RESERVED_API[@]}"; then
            log_warn "Skipping api/$base - collides with a builder-generated route. Rename it and re-import."
            continue
        fi
        cp -r "$entry" "$DEST/api/"
    done
    log_info "API routes copied."
fi

# --- 4. Other app/ routes -> routes/ (everything except homepage/api/layout/css) ---
for entry in "$APP"/*; do
    [[ -e "$entry" ]] || continue
    base="$(basename "$entry")"
    case "$base" in
        page.tsx|page.jsx|layout.tsx|layout.jsx|api|globals.css|favicon.ico) continue ;;
    esac
    if in_list "$base" "${RESERVED_ROUTES[@]}"; then
        log_warn "Skipping app/$base - collides with a builder-generated page. Rename it and re-import."
        continue
    fi
    mkdir -p "$DEST/routes"
    cp -r "$entry" "$DEST/routes/"
done
[[ -d "$DEST/routes" ]] && log_info "Nested routes copied."

# --- 5. components/, hooks/, public/ -----------------------------------------
for d in components hooks public; do
    if [[ -d "$ROOT/$d" ]]; then
        cp -r "$ROOT/$d" "$DEST/$d"
        log_info "$d/ copied."
    elif [[ "$d" == "public" && -d "$SRC/public" ]]; then
        cp -r "$SRC/public" "$DEST/public"
        log_info "public/ copied."
    fi
done
# The builder owns ClientAnalytics.tsx
if [[ -f "$DEST/components/ClientAnalytics.tsx" ]]; then
    log_warn "Removing components/ClientAnalytics.tsx - builder provides its own."
    rm -f "$DEST/components/ClientAnalytics.tsx"
fi

# --- 6. lib/ (minus files the builder generates) -----------------------------
if [[ -d "$ROOT/lib" ]]; then
    cp -r "$ROOT/lib" "$DEST/lib"
    for f in "${RESERVED_LIB[@]}"; do
        if [[ -f "$DEST/lib/$f" ]]; then
            log_warn "Removing lib/$f - builder provides its own (prisma client / auth / cn helper)."
            rm -f "$DEST/lib/$f"
        fi
    done
    log_info "lib/ copied."
fi

# --- 7. Prisma models -> prisma/schema.partial.prisma ------------------------
if [[ -f "$SRC/prisma/schema.prisma" ]]; then
    mkdir -p "$DEST/prisma"
    node -e '
      const fs = require("fs");
      const src = fs.readFileSync(process.argv[1], "utf8");
      const reserved = new Set(["User", "Analytics", "ApiStats"]);
      const re = /^(generator|datasource|model|enum|view|type)\s+(\w+)\s*\{[\s\S]*?^\}/gm;
      const out = [];
      let m;
      while ((m = re.exec(src))) {
        const [block, kind, name] = m;
        if (kind === "generator" || kind === "datasource") continue;
        if (reserved.has(name)) { console.error("[WARN]  Skipping Prisma model " + name + " - builder defines it."); continue; }
        if (/@db\./.test(block)) console.error("[WARN]  " + name + " uses @db.* attributes: these are MySQL-only and break the SQLite option.");
        if (kind === "enum") console.error("[WARN]  enum " + name + ": Prisma 5 does not support enums on SQLite - use a String field instead.");
        if (/\bJson\??\s/.test(block)) console.error("[WARN]  " + name + " uses Json: unsupported on SQLite in Prisma 5 - store a String and JSON.parse it.");
        if (/\b(String|Int|Float|Boolean|DateTime|BigInt|Decimal|Bytes)\[\]/.test(block)) console.error("[WARN]  " + name + " uses a scalar list: unsupported on SQLite - use a relation or a String.");
        if (/\bUser\b/.test(block)) console.error("[WARN]  " + name + " references User - the builder User model has different fields.");
        out.push(block);
      }
      if (out.length) fs.writeFileSync(process.argv[2], "// Imported models - appended to the base schema by 04a-app-init.sh\n\n" + out.join("\n\n") + "\n");
    ' "$SRC/prisma/schema.prisma" "$DEST/prisma/schema.partial.prisma"
    if [[ -f "$DEST/prisma/schema.partial.prisma" ]]; then
        log_info "Prisma models extracted."
    else
        rmdir "$DEST/prisma"
        log_info "No custom Prisma models found."
    fi
fi

# --- 8. package.json -> manifest.json (only deps the builder does not install) ---
if [[ -f "$SRC/package.json" ]]; then
    node -e '
      const fs = require("fs");
      const pkg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const builtin = new Set([
        "next","react","react-dom","@prisma/client","prisma","bcryptjs","jsonwebtoken",
        "clsx","tailwind-merge","typescript","tailwindcss","@tailwindcss/postcss","@tailwindcss/turbopack",
        "postcss","eslint","eslint-config-next",
        "@types/node","@types/react","@types/react-dom","@types/bcryptjs","@types/jsonwebtoken"
      ]);
      // Keep the version only when it is a simple, shell-safe spec
      const conv = (o) => Object.entries(o || {})
        .filter(([n]) => !builtin.has(n))
        .map(([n, v]) => /^[\^~]?\d[\w.\-]*$/.test(v) ? n + "@" + v : n);
      const manifest = { name: process.argv[2], dependencies: conv(pkg.dependencies), devDependencies: conv(pkg.devDependencies) };
      fs.writeFileSync(process.argv[3], JSON.stringify(manifest, null, 2) + "\n");
    ' "$SRC/package.json" "$NAME" "$DEST/manifest.json"
    log_info "manifest.json generated."
else
    echo '{ "name": "'"$NAME"'", "dependencies": [], "devDependencies": [] }' > "$DEST/manifest.json"
    log_warn "No package.json found - empty manifest.json written."
fi

# --- 9. Env vars: .env.example only; strip vars the builder already sets -----
for envf in .env.example .env.template; do
    if [[ -f "$SRC/$envf" ]]; then
        grep -Ev '^(DATABASE_URL|JWT_SECRET|ADMIN_USERNAME|NEXT_PUBLIC_SITE_URL|NODE_ENV|PORT)=' "$SRC/$envf" > "$DEST/.env.template" || true
        [[ -s "$DEST/.env.template" ]] || rm -f "$DEST/.env.template"
        log_info "Env template generated from $envf (builder-owned vars removed)."
        break
    fi
done
[[ -f "$SRC/.env" ]] && log_warn ".env found and deliberately NOT copied (may contain secrets)."

# --- 10. Global CSS -> globals.css.append (drop duplicate tailwind imports) ---
if [[ -f "$APP/globals.css" ]]; then
    grep -Ev '^\s*@import\s+"tailwindcss"|^\s*@tailwind\s' "$APP/globals.css" > "$DEST/globals.css.append" || true
    if grep -q '[^[:space:]]' "$DEST/globals.css.append"; then
        log_info "globals.css.append generated."
    else
        rm -f "$DEST/globals.css.append"
    fi
fi

# --- 11. Tailwind config (v3-style projects) ---------------------------------
[[ -f "$SRC/tailwind.config.ts" ]] && cp "$SRC/tailwind.config.ts" "$DEST/tailwind.config.ts" && log_info "tailwind.config.ts copied."

# --- Done --------------------------------------------------------------------
log_info "Template '$NAME' ready at $DEST"
log_info "Run ./setup.sh and pick category '$CATEGORY', variant '$VARIANT' from the menu."