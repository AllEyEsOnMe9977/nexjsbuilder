# =============================================================================
# 04a-app-init.sh
# Project directory creation, Next.js scaffolding, dependencies, Prisma schema
# Sourced by 04-app.sh — expects PROJECT_DIR, DB_TYPE, generate_password(),
# log_info() to be defined by earlier modules (01-utils.sh, 02-config.sh).
# =============================================================================

# Create project directory
log_info "Creating project directory at $PROJECT_DIR..."
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Create Next.js app
log_info "Creating Next.js application..."
export NEXT_TELEMETRY_DISABLED=1
npx --yes create-next-app@latest . --typescript --tailwind --app --no-src-dir --import-alias "@/*" --use-npm --yes

# Install additional dependencies
log_info "Installing additional dependencies..."
npm install @prisma/client@5 bcryptjs jsonwebtoken
npm install -D prisma@5 @types/bcryptjs @types/jsonwebtoken

# Initialize Prisma
log_info "Setting up Prisma ORM..."
npx prisma init --datasource-provider $([[ "$DB_TYPE" == "sqlite" ]] && echo "sqlite" || echo "mysql")

# Create Prisma schema
log_info "Creating database schema..."
cat > prisma/schema.prisma << EOF
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "$([[ "$DB_TYPE" == "sqlite" ]] && echo "sqlite" || echo "mysql")"
  url      = env("DATABASE_URL")
}

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
  userAgent     String?  $([[ "$DB_TYPE" == "mariadb" ]] && echo "@db.Text" || echo "")
  method        String
  path          String
  statusCode    Int
  responseTime  Int
  referer       String?  $([[ "$DB_TYPE" == "mariadb" ]] && echo "@db.Text" || echo "")
  country       String?  $([[ "$DB_TYPE" == "mariadb" ]] && echo "@db.VarChar(100)" || echo "")
  city          String?  $([[ "$DB_TYPE" == "mariadb" ]] && echo "@db.VarChar(100)" || echo "")
  device        String?  $([[ "$DB_TYPE" == "mariadb" ]] && echo "@db.VarChar(50)" || echo "")
  browser       String?  $([[ "$DB_TYPE" == "mariadb" ]] && echo "@db.VarChar(50)" || echo "")
  os            String?  $([[ "$DB_TYPE" == "mariadb" ]] && echo "@db.VarChar(50)" || echo "")
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
EOF