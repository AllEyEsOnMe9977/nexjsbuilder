#!/bin/bash

# Next.js Automated Setup Script with SSL, Nginx, Database, and Analytics
# Run as root or with sudo

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root or with sudo"
fi

# Generate random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-24
}

# Validate and sanitize project name
sanitize_project_name() {
    local name=$1
    # Convert to lowercase
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    # Replace spaces and underscores with hyphens
    name=$(echo "$name" | tr '_' '-' | tr ' ' '-')
    # Remove any characters that aren't alphanumeric or hyphens
    name=$(echo "$name" | sed 's/[^a-z0-9-]//g')
    # Remove leading/trailing hyphens
    name=$(echo "$name" | sed 's/^-*//;s/-*$//')
    # Ensure it doesn't start with a number
    if [[ $name =~ ^[0-9] ]]; then
        name="app-$name"
    fi
    echo "$name"
}

# Validate domain
validate_domain() {
    local domain=$1
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    return 0
}

# Validate email
validate_email() {
    local email=$1
    if [[ ! $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

# Check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0
    else
        return 1
    fi
}

# Get domain from user with validation
log_step "Domain Configuration"
while true; do
    read -p "Enter your domain name (e.g., example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        log_warn "Domain cannot be empty. Please try again."
        continue
    fi
    if validate_domain "$DOMAIN"; then
        break
    else
        log_warn "Invalid domain format. Please try again."
    fi
done

# Get email for Let's Encrypt with validation
while true; do
    read -p "Enter your email for SSL certificate notifications: " EMAIL
    if [[ -z "$EMAIL" ]]; then
        log_warn "Email cannot be empty. Please try again."
        continue
    fi
    if validate_email "$EMAIL"; then
        break
    else
        log_warn "Invalid email format. Please try again."
    fi
done

# Get project name with validation
while true; do
    read -p "Enter project name (default: nextjs-app): " PROJECT_NAME_INPUT
    PROJECT_NAME_INPUT=${PROJECT_NAME_INPUT:-nextjs-app}
    PROJECT_NAME=$(sanitize_project_name "$PROJECT_NAME_INPUT")
    
    if [[ -z "$PROJECT_NAME" ]]; then
        log_warn "Invalid project name. Please use letters, numbers, and hyphens."
        continue
    fi
    
    if [[ ${#PROJECT_NAME} -lt 3 ]]; then
        log_warn "Project name must be at least 3 characters long."
        continue
    fi
    
    log_info "Project name will be: $PROJECT_NAME"
    break
done

# Database selection
log_step "Database Configuration"
echo "Select database:"
echo "1) SQLite (lightweight, file-based)"
echo "2) MariaDB (full-featured SQL server)"
while true; do
    read -p "Enter choice [1-2]: " DB_CHOICE
    case $DB_CHOICE in
        1|2)
            break
            ;;
        *)
            log_warn "Invalid choice. Please enter 1 or 2."
            ;;
    esac
done

DB_TYPE=""
DB_NAME="${PROJECT_NAME//-/_}_db"
DB_USER="${PROJECT_NAME//-/_}_user"
DB_PASSWORD=$(generate_password)
DB_HOST="localhost"
DB_PORT="3306"

case $DB_CHOICE in
    1)
        DB_TYPE="sqlite"
        log_info "SQLite selected"
        ;;
    2)
        DB_TYPE="mariadb"
        log_info "MariaDB selected"
        ;;
esac

# Admin user configuration
log_step "Admin User Configuration"
while true; do
    read -p "Enter admin username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    # Sanitize username
    ADMIN_USER=$(echo "$ADMIN_USER" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')
    
    if [[ -z "$ADMIN_USER" ]]; then
        log_warn "Username cannot be empty after sanitization."
        continue
    fi
    
    if [[ ${#ADMIN_USER} -lt 3 ]]; then
        log_warn "Username must be at least 3 characters long."
        continue
    fi
    
    break
done

read -p "Enter admin password (leave empty to auto-generate): " ADMIN_PASSWORD
if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD=$(generate_password)
    AUTO_GENERATED_PASS=true
else
    AUTO_GENERATED_PASS=false
    if [[ ${#ADMIN_PASSWORD} -lt 8 ]]; then
        log_warn "Password is less than 8 characters. Consider using a stronger password."
    fi
fi

# ADD THIS ENTIRE SECTION HERE:
# Template selection
log_step "Template Selection"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Select homepage template:"
echo "1) Blank (minimal welcome page)"
echo "2) Shop (e-commerce template)"
while true; do
    read -p "Enter choice [1-2]: " TEMPLATE_CHOICE
    case $TEMPLATE_CHOICE in
        1)
            TEMPLATE_FILE="blank.tsx"
            # Look for templates relative to the script location
            TEMPLATE_PATH="$SCRIPT_DIR/templates/$TEMPLATE_FILE"

            # If not found, try current directory
            if [[ ! -f "$TEMPLATE_PATH" ]]; then
                TEMPLATE_PATH="$(pwd)/templates/$TEMPLATE_FILE"
            fi
            log_info "Blank template selected"
            break
            ;;
        2)
            TEMPLATE_FILE="shop.tsx"
            # Look for templates relative to the script location
            TEMPLATE_PATH="$SCRIPT_DIR/templates/$TEMPLATE_FILE"

            # If not found, try current directory
            if [[ ! -f "$TEMPLATE_PATH" ]]; then
                TEMPLATE_PATH="$(pwd)/templates/$TEMPLATE_FILE"
            fi
            log_info "Shop template selected"
            break
            ;;
        *)
            log_warn "Invalid choice. Please enter 1 or 2."
            ;;
    esac
done

# Check if template file exists
if [[ ! -f "$TEMPLATE_PATH" ]]; then
    log_error "Template file not found: $TEMPLATE_PATH"
fi

log_info "Using template: $TEMPLATE_PATH"
# END OF ADDED SECTION

PROJECT_DIR="/var/www/$PROJECT_NAME"
NGINX_AVAILABLE="/etc/nginx/sites-available/$DOMAIN"
NGINX_ENABLED="/etc/nginx/sites-enabled/$DOMAIN"

# Check if project directory already exists
if [[ -d "$PROJECT_DIR" ]]; then
    log_warn "Project directory $PROJECT_DIR already exists."
    read -p "Do you want to remove it and continue? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        log_error "Setup cancelled by user."
    fi
    log_info "Removing existing directory..."
    rm -rf "$PROJECT_DIR"
fi

# Check if nginx site already exists
if [[ -f "$NGINX_AVAILABLE" ]]; then
    log_warn "Nginx configuration for $DOMAIN already exists."
    read -p "Do you want to overwrite it? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        log_error "Setup cancelled by user."
    fi
    rm -f "$NGINX_AVAILABLE" "$NGINX_ENABLED"
fi

# Check if service already exists
if systemctl list-unit-files | grep -q "^$PROJECT_NAME.service"; then
    log_warn "Service $PROJECT_NAME already exists."
    systemctl stop "$PROJECT_NAME" 2>/dev/null || true
    systemctl disable "$PROJECT_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/$PROJECT_NAME.service"
fi

log_info "Starting setup for $DOMAIN..."

# Update system
log_info "Updating system packages..."
apt-get update
apt-get upgrade -y

# Create swap if not exists (prevents OOM during build)
if ! swapon --show | grep -q '/swapfile'; then
    log_info "Creating 2GB swap file to prevent build failures..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    log_info "Swap created successfully"
fi

# Check available RAM
TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
if [[ $TOTAL_RAM -lt 2048 ]]; then
    log_warn "Low RAM detected (${TOTAL_RAM}MB). Build may be slow or fail."
    log_warn "Recommended: At least 2GB RAM. Current: ${TOTAL_RAM}MB"
    read -p "Continue anyway? (yes/no): " CONFIRM_RAM
    if [[ "$CONFIRM_RAM" != "yes" ]]; then
        log_error "Setup cancelled due to insufficient RAM."
    fi
    # Reduce Node memory limit for low-RAM systems
    export NODE_OPTIONS="--max-old-space-size=1024"
else
    export NODE_OPTIONS="--max-old-space-size=1536"
fi

# Install Node.js and npm if not installed
if ! command -v node &> /dev/null; then
    log_info "Installing Node.js and npm..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
else
    log_info "Node.js already installed ($(node -v))"
fi

# Install lsof if missing (required for robust port detection)
if ! command -v lsof &> /dev/null; then
    log_info "Installing lsof for port detection..."
    apt-get install -y lsof
fi

# Install nginx if not installed
if ! command -v nginx &> /dev/null; then
    log_info "Installing Nginx..."
    apt-get install -y nginx
else
    log_info "Nginx already installed"
fi

# Install certbot if not installed
if ! command -v certbot &> /dev/null; then
    log_info "Installing Certbot..."
    apt-get install -y certbot python3-certbot-nginx
else
    log_info "Certbot already installed"
fi

# Install database
if [[ "$DB_TYPE" == "mariadb" ]]; then
    if ! command -v mysql &> /dev/null; then
        log_info "Installing MariaDB..."
        apt-get install -y mariadb-server
        systemctl start mariadb
        systemctl enable mariadb
    else
        log_info "MariaDB already installed"
    fi
    
    # Check if database exists
    if mysql -e "USE $DB_NAME;" 2>/dev/null; then
        log_warn "Database $DB_NAME already exists. Dropping and recreating..."
        mysql -e "DROP DATABASE $DB_NAME;"
    fi
    
    # Secure MariaDB and create database
    log_info "Creating MariaDB database and user..."
    mysql -e "CREATE DATABASE $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -e "DROP USER IF EXISTS '$DB_USER'@'localhost';"
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    
    DB_URL="mysql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
else
    log_info "SQLite will be used (no installation needed)"
    DB_URL="file:./analytics.db"
fi

# Find a random free port between 3000 and 9000
find_free_port() {
    local port
    local attempts=0
    local max_attempts=100
    
    while [[ $attempts -lt $max_attempts ]]; do
        # Generate random port between 3000 and 9000
        port=$(shuf -i 3000-9000 -n 1)
        
        # Check if port is in use using lsof
        if ! lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo $port
            return 0
        fi
        
        attempts=$((attempts + 1))
    done
    
    log_error "Could not find a free port after $max_attempts attempts"
}

log_info "Scanning for a random available port..."
APP_PORT=$(find_free_port)
log_info "Selected available port: $APP_PORT"

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
  country       String?  @db.VarChar(100)
  city          String?  @db.VarChar(100)
  device        String?  @db.VarChar(50)
  browser       String?  @db.VarChar(50)
  os            String?  @db.VarChar(50)
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

# Create .env file
# Create .env file
log_info "Creating environment configuration..."

# Construct proper DATABASE_URL based on DB type
if [[ "$DB_TYPE" == "mariadb" ]]; then
    FINAL_DB_URL="mysql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?connection_limit=5&pool_timeout=10"
else
    FINAL_DB_URL="file:./analytics.db"
fi

cat > .env << EOF
DATABASE_URL="$FINAL_DB_URL"
JWT_SECRET="$(generate_password)"
ADMIN_USERNAME="$ADMIN_USER"
# REMOVE THIS LINE: ADMIN_PASSWORD="$ADMIN_PASSWORD"
NEXT_PUBLIC_SITE_URL="https://$DOMAIN"
NODE_ENV=production
PORT=$APP_PORT
EOF

# Secure .env file
chmod 600 .env

# Ensure .env is in .gitignore
if [[ -f .gitignore ]]; then
    if ! grep -q "^\.env$" .gitignore; then
        echo ".env" >> .gitignore
    fi
else
    echo ".env" > .gitignore
fi

# Create lib directory structure
mkdir -p lib

# Create database utility
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

# Create auth utility
cat > lib/auth.ts << 'EOF'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this'

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12)
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash)
}

export function generateToken(userId: string, username: string): string {
  return jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '7d' })
}

export function verifyToken(token: string): { userId: string; username: string } | null {
  try {
    return jwt.verify(token, JWT_SECRET) as { userId: string; username: string }
  } catch {
    return null
  }
}
EOF

# Create analytics utility with improved error handling
# Create analytics utility with improved error handling
cat > lib/analytics.ts << 'EOF'
import { prisma } from './db'

interface AnalyticsData {
  ip: string
  userAgent?: string
  method: string
  path: string
  statusCode: number
  responseTime: number
  referer?: string
}

// Helper to parse User Agent (Basic)
function parseUserAgent(ua: string) {
  const device = /mobile/i.test(ua) ? 'Mobile' : /tablet|ipad/i.test(ua) ? 'Tablet' : 'Desktop'
  
  let browser = 'Other'
  if (/chrome/i.test(ua) && !/edge|edg/i.test(ua)) browser = 'Chrome'
  else if (/firefox/i.test(ua)) browser = 'Firefox'
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari'
  else if (/edge|edg/i.test(ua)) browser = 'Edge'

  let os = 'Other'
  if (/windows/i.test(ua)) os = 'Windows'
  else if (/mac os/i.test(ua)) os = 'macOS'
  else if (/linux/i.test(ua)) os = 'Linux'
  else if (/android/i.test(ua)) os = 'Android'
  else if (/ios|iphone|ipad/i.test(ua)) os = 'iOS'

  return { device, browser, os }
}

export async function logAnalytics(data: AnalyticsData) {
  try {
    const { device, browser, os } = parseUserAgent(data.userAgent || '')
    
    await prisma.analytics.create({
      data: {
        ip: data.ip,
        userAgent: data.userAgent,
        method: data.method,
        path: data.path,
        statusCode: data.statusCode,
        responseTime: data.responseTime,
        referer: data.referer,
        device,
        browser,
        os,
        bytesIn: 0,
        bytesOut: 0,
      },
    })
  } catch (error) {
    console.error('Analytics logging error:', error)
  }
}

export async function getAnalyticsSummary(days: number = 7) {
  const startDate = new Date()
  startDate.setDate(startDate.getDate() - days)
  
  try {
    // Run queries in parallel
    const [totalVisits, uniqueVisitorsRaw, topPages, deviceStats, browserStats] = await Promise.all([
      prisma.analytics.count({
        where: { timestamp: { gte: startDate } },
      }),
      
      prisma.analytics.groupBy({
        by: ['ip'],
        where: { timestamp: { gte: startDate } },
      }),
      
      prisma.analytics.groupBy({
        by: ['path'],
        where: { timestamp: { gte: startDate } },
        _count: { path: true },
        orderBy: { _count: { path: 'desc' } },
        take: 10,
      }),
      
      prisma.analytics.groupBy({
        by: ['device'],
        where: { timestamp: { gte: startDate }, device: { not: null } },
        _count: { device: true },
      }),
      
      prisma.analytics.groupBy({
        by: ['browser'],
        where: { timestamp: { gte: startDate }, browser: { not: null } },
        _count: { browser: true },
      }),
    ])
    
    return {
      totalVisits: totalVisits || 0,
      uniqueVisitors: uniqueVisitorsRaw ? uniqueVisitorsRaw.length : 0,
      topPages: topPages.map(p => ({ 
        path: p.path || '/', 
        visits: p._count?.path || 0 
      })),
      deviceStats: deviceStats.map(d => ({ 
        device: d.device || 'Unknown', 
        count: d._count?.device || 0 
      })),
      browserStats: browserStats.map(b => ({ 
        browser: b.browser || 'Unknown', 
        count: b._count?.browser || 0 
      })),
    }
  } catch (error) {
    console.error('Error fetching analytics summary:', error)
    // Return empty structure on error to prevent UI crash
    return {
      totalVisits: 0,
      uniqueVisitors: 0,
      topPages: [],
      deviceStats: [],
      browserStats: [],
    }
  }
}
EOF

# Create internal analytics recording endpoint (Bridge for Middleware)
mkdir -p app/api/analytics/record
cat > app/api/analytics/record/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { logAnalytics } from '@/lib/analytics'

export const runtime = 'nodejs' 

export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('x-internal-secret')
    // Simple security check
    if (authHeader !== process.env.JWT_SECRET) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const data = await request.json()
    
    // Log it
    await logAnalytics(data)
    
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Analytics Record Error:', error)
    return NextResponse.json({ error: 'Internal Error' }, { status: 500 })
  }
}
EOF


# Create improved middleware with direct function call
# Create improved middleware with direct function call
cat > middleware.ts << 'EOF'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
// Ensure we're using the same port as the app
if (!process.env.PORT) {
  console.warn('[Middleware] PORT env variable not set, using default 3000')
}
export async function middleware(request: NextRequest) {
  const response = NextResponse.next()
  
  const pathname = request.nextUrl.pathname

  // 1. Ignore internal API calls to prevent infinite loops
  if (pathname.startsWith('/api/analytics/record')) {
    return response
  }

  // 2. Ignore static files and Next.js internals
  if (
    pathname.startsWith('/_next') || 
    pathname.includes('.') || 
    pathname.startsWith('/favicon.ico')
  ) {
    return response
  }

  // ADD THIS NEW CHECK:
  // 3. Ignore requests from localhost to prevent internal loops
  const forwardedFor = request.headers.get('x-forwarded-for')
  const realIp = request.headers.get('x-real-ip')
  if (forwardedFor?.includes('127.0.0.1') || realIp === '127.0.0.1') {
    return response
  }

  const startTime = Date.now()
  
  // Prepare payload
  // We grab IP from headers because request.ip is sometimes unreliable in proxies
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             '127.0.0.1'
             
  const analyticsPayload = {
    ip,
    userAgent: request.headers.get('user-agent'),
    method: request.method,
    path: pathname,
    statusCode: 200, // We assume success for the middleware pass-through
    responseTime: Date.now() - startTime,
    referer: request.headers.get('referer'),
  }

  // 3. Send to internal API using LOCALHOST explicitly
  // We use process.env.PORT or default to 3000
  // Use explicit localhost with fallback
  const port = process.env.PORT || '3000'
  const internalApiUrl = `http://localhost:${port}/api/analytics/record`

  // Fire and forget - don't await
  try {
    fetch(internalApiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-internal-secret': process.env.JWT_SECRET || '',
      },
      body: JSON.stringify(analyticsPayload),
      signal: AbortSignal.timeout(5000), // ADD TIMEOUT
    }).catch(err => {
      console.error(`[Middleware] Analytics request failed: ${err.message}`)
    })
  } catch (err) {
    // Silent fail - don't block user requests
  }

  return response
}

export const config = {
  matcher: [
    // Match everything except static files
    '/((?!api/|_next/static|_next/image|favicon.ico).*)',
  ],
}
EOF

# Create API routes directory structure
log_info "Creating API directory structure..."
mkdir -p app/api/auth/login
mkdir -p app/api/analytics/summary
mkdir -p app/api/analytics/detailed
mkdir -p app/api/analytics/traffic
mkdir -p app/api/health
mkdir -p app/api/example

# Health check endpoint
cat > app/api/health/route.ts << 'EOF'
import { NextResponse } from 'next/server'
import { prisma } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

export async function GET() {
  try {
    await prisma.$queryRaw`SELECT 1`
    
    return NextResponse.json({ 
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: 'connected',
      uptime: process.uptime()
    })
  } catch (error) {
    console.error('Health check failed:', error)
    return NextResponse.json({ 
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 503 })
  }
}
EOF

# Auth login API
cat > app/api/auth/login/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/db'
import { verifyPassword, generateToken } from '@/lib/auth'

export const runtime = 'nodejs'

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json()
    
    if (!username || !password) {
      return NextResponse.json({ error: 'Username and password required' }, { status: 400 })
    }
    
    const user = await prisma.user.findUnique({
      where: { username },
    })
    
    if (!user) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
    }
    
    const valid = await verifyPassword(password, user.password)
    
    if (!valid) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
    }
    
    const token = generateToken(user.id, user.username)
    
    return NextResponse.json({ token, username: user.username })
  } catch (error) {
    console.error('Login error:', error)
    return NextResponse.json({ 
      error: 'Login failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
EOF

# Analytics API
cat > app/api/analytics/summary/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'
import { getAnalyticsSummary } from '@/lib/analytics'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get('authorization')?.replace('Bearer ', '')
    
    if (!token || !verifyToken(token)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    
    const { searchParams } = new URL(request.url)
    const days = parseInt(searchParams.get('days') || '7')
    
    const summary = await getAnalyticsSummary(days)
    
    return NextResponse.json(summary, {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
      },
    })
  } catch (error) {
    console.error('Analytics summary error:', error)
    return NextResponse.json({ 
      error: 'Failed to fetch analytics',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
EOF

# Detailed analytics API
cat > app/api/analytics/detailed/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'
import { prisma } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get('authorization')?.replace('Bearer ', '')
    
    if (!token || !verifyToken(token)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    
    const { searchParams } = new URL(request.url)
    const days = parseInt(searchParams.get('days') || '7')
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '50')
    
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)
    
    const [visits, total] = await Promise.all([
      prisma.analytics.findMany({
        where: { timestamp: { gte: startDate } },
        orderBy: { timestamp: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.analytics.count({
        where: { timestamp: { gte: startDate } },
      }),
    ])
    
    return NextResponse.json({
      visits,
      total,
      page,
      pages: Math.ceil(total / limit),
    }, {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
      },
    })
  } catch (error) {
    console.error('Detailed analytics error:', error)
    return NextResponse.json({ 
      error: 'Failed to fetch detailed analytics',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
EOF

# Traffic stats API
cat > app/api/analytics/traffic/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'
import { prisma } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get('authorization')?.replace('Bearer ', '')
    
    if (!token || !verifyToken(token)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    
    const { searchParams } = new URL(request.url)
    const days = parseInt(searchParams.get('days') || '7')
    
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)
    
    const traffic = await prisma.analytics.findMany({
      where: { timestamp: { gte: startDate } },
      select: {
        timestamp: true,
        bytesIn: true,
        bytesOut: true,
      },
      orderBy: { timestamp: 'asc' },
    })
    
    return NextResponse.json({ traffic }, {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
      },
    })
  } catch (error) {
    console.error('Traffic stats error:', error)
    return NextResponse.json({ 
      error: 'Failed to fetch traffic stats',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
EOF

# Example API endpoint
cat > app/api/example/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  return NextResponse.json({
    message: 'Hello from API!',
    timestamp: new Date().toISOString(),
    method: 'GET',
  })
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    
    return NextResponse.json({
      message: 'Data received successfully',
      data: body,
      timestamp: new Date().toISOString(),
      method: 'POST',
    })
  } catch (error) {
    return NextResponse.json({
      error: 'Invalid JSON',
    }, { status: 400 })
  }
}
EOF

# Create client analytics component
log_info "Creating client analytics tracking..."
mkdir -p components

cat > components/ClientAnalytics.tsx << 'EOF'
'use client'

import { useEffect } from 'react'
import { usePathname } from 'next/navigation'

export function ClientAnalytics() {
  const pathname = usePathname()

  useEffect(() => {
    const sendAnalytics = async () => {
      try {
        await fetch('/api/analytics/track', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            path: pathname,
            timestamp: new Date().toISOString(),
          }),
        })
      } catch (error) {
        console.error('[Client] Analytics error:', error)
      }
    }

    sendAnalytics()
  }, [pathname])

  return null
}
EOF

# Create client tracking API
mkdir -p app/api/analytics/track
cat > app/api/analytics/track/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { logAnalytics } from '@/lib/analytics'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { path } = body
    
    const forwardedFor = request.headers.get('x-forwarded-for')
    const realIp = request.headers.get('x-real-ip')
    let ip = '127.0.0.1'
    
    if (forwardedFor) {
      ip = forwardedFor.split(',')[0].trim()
    } else if (realIp) {
      ip = realIp
    }
    
    if (ip.startsWith('::ffff:')) {
      ip = ip.substring(7)
    }
    
    const userAgent = request.headers.get('user-agent') || undefined
    const referer = request.headers.get('referer') || undefined
    
    await logAnalytics({
      ip,
      userAgent,
      method: 'GET',
      path: path || '/',
      statusCode: 200,
      responseTime: 0,
      referer,
    })
    
    return NextResponse.json({ success: true })
  } catch (error) {
    return NextResponse.json(
      { success: false },
      { status: 500 }
    )
  }
}
EOF

# Create test data endpoint for debugging
mkdir -p app/api/analytics/test
cat > app/api/analytics/test/route.ts << 'EOF'
import { NextResponse } from 'next/server'
import { prisma } from '@/lib/db'

export const runtime = 'nodejs'

export async function GET() {
  try {
    // Create test analytics data
    await prisma.analytics.create({
      data: {
        ip: '127.0.0.1',
        userAgent: 'Test Browser',
        method: 'GET',
        path: '/test',
        statusCode: 200,
        responseTime: 100,
        device: 'Desktop',
        browser: 'Chrome',
        os: 'Linux',
      },
    })
    
    const count = await prisma.analytics.count()
    
    return NextResponse.json({ 
      success: true,
      message: 'Test data created',
      totalRecords: count
    })
  } catch (error) {
    return NextResponse.json({ 
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
EOF

# Create admin dashboard
# Create admin dashboard
mkdir -p app/admin
cat > app/admin/page.tsx << 'EOF'
'use client'

import { useState, useEffect, useCallback } from 'react'

interface AnalyticsSummary {
  totalVisits: number
  uniqueVisitors: number
  topPages: { path: string; visits: number }[]
  deviceStats: { device: string; count: number }[]
  browserStats: { browser: string; count: number }[]
}

export default function AdminDashboard() {
  const [token, setToken] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null)
  const [days, setDays] = useState(7)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const fetchAnalytics = useCallback(async (authToken: string, daysParam: number) => {
    setLoading(true)
    setError('')
    
    try {
      const res = await fetch(`/api/analytics/summary?days=${daysParam}`, {
        headers: { 
          Authorization: `Bearer ${authToken}`,
          'Cache-Control': 'no-cache'
        },
      })

      if (res.ok) {
        const data = await res.json()
        setAnalytics(data)
      } else {
        if (res.status === 401) {
          handleLogout()
        } else {
          setError('Failed to load data')
        }
      }
    } catch (err) {
      setError('Connection error')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const savedToken = localStorage.getItem('adminToken')
    if (savedToken) {
      setToken(savedToken)
      setIsLoggedIn(true)
      fetchAnalytics(savedToken, days)
    }
  }, [days, fetchAnalytics])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      if (res.ok) {
        const data = await res.json()
        setToken(data.token)
        localStorage.setItem('adminToken', data.token)
        setIsLoggedIn(true)
        fetchAnalytics(data.token, days)
      } else {
        const data = await res.json()
        setError(data.error || 'Invalid credentials')
      }
    } catch (error) {
      setError('Login failed. Please check your connection.')
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = () => {
    setToken('')
    localStorage.removeItem('adminToken')
    setIsLoggedIn(false)
    setAnalytics(null)
  }

  if (!isLoggedIn) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <div className="bg-white p-8 rounded-lg shadow-md w-96">
          <h1 className="text-2xl font-bold mb-6 text-gray-800">Admin Login</h1>
          {error && (
            <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md text-sm">
              {error}
            </div>
          )}
          <form onSubmit={handleLogin}>
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2 text-gray-700">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900"
                required
              />
            </div>
            <div className="mb-6">
              <label className="block text-sm font-medium mb-2 text-gray-700">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition-colors"
            >
              {loading ? 'Logging in...' : 'Login'}
            </button>
          </form>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Analytics Dashboard</h1>
          <button
            onClick={handleLogout}
            className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 transition-colors"
          >
            Logout
          </button>
        </div>

        <div className="mb-6 flex gap-2">
          {[7, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-4 py-2 rounded-md transition-colors ${
                days === d ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-100'
              }`}
            >
              Last {d} days
            </button>
          ))}
        </div>

        {loading && !analytics ? (
          <div className="text-center py-12 text-gray-600">Loading analytics...</div>
        ) : analytics ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h2 className="text-sm font-medium text-gray-500 uppercase">Total Visits</h2>
              <p className="mt-2 text-3xl font-semibold text-gray-900">{analytics.totalVisits}</p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <h2 className="text-sm font-medium text-gray-500 uppercase">Unique Visitors</h2>
              <p className="mt-2 text-3xl font-semibold text-gray-900">{analytics.uniqueVisitors}</p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <h2 className="text-sm font-medium text-gray-500 uppercase">Visits / User</h2>
              <p className="mt-2 text-3xl font-semibold text-gray-900">
                {analytics.uniqueVisitors > 0
                  ? (analytics.totalVisits / analytics.uniqueVisitors).toFixed(1)
                  : '0.0'}
              </p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow col-span-1 md:col-span-2">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Top Pages</h3>
              <div className="space-y-3">
                {analytics.topPages.map((page, i) => (
                  <div key={i} className="flex justify-between items-center border-b border-gray-100 last:border-0 pb-2 last:pb-0">
                    <span className="text-sm text-gray-600 truncate">{page.path}</span>
                    <span className="text-sm font-semibold text-gray-900">{page.visits}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Device Types</h3>
              <div className="space-y-3">
                {analytics.deviceStats.map((stat, i) => (
                  <div key={i} className="flex justify-between items-center">
                    <span className="text-sm text-gray-600">{stat.device}</span>
                    <span className="text-sm font-semibold text-gray-900">{stat.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  )
}
EOF

# Create home page
# Create info page (Moved original home content here)
mkdir -p app/info
cat > app/info/page.tsx << 'EOF'
export default function Info() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24 bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="z-10 max-w-5xl w-full items-center justify-center font-mono text-sm">
        <h1 className="text-5xl font-bold mb-4 text-center bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
          Next.js Setup Complete! 🚀
        </h1>
        <p className="text-xl text-center text-gray-700 mb-8">
          Your secure Next.js application with API and Analytics is now running
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-8">
          <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm hover:shadow-md transition-shadow">
            <h2 className="text-xl font-semibold mb-2 text-gray-900">API Endpoint</h2>
            <p className="text-sm text-gray-600 mb-4">
              Test the example API endpoint
            </p>
            <a
              href="/api/example"
              className="text-blue-600 hover:text-blue-800 hover:underline font-medium"
              target="_blank"
              rel="noopener noreferrer"
            >
              /api/example →
            </a>
          </div>
          <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm hover:shadow-md transition-shadow">
            <h2 className="text-xl font-semibold mb-2 text-gray-900">Admin Dashboard</h2>
            <p className="text-sm text-gray-600 mb-4">
              View analytics and insights
            </p>
            <a
              href="/admin"
              className="text-blue-600 hover:text-blue-800 hover:underline font-medium"
            >
              /admin →
            </a>
          </div>
        </div>
        <div className="mt-8 p-4 bg-white border border-gray-200 rounded-lg">
          <p className="text-sm text-gray-500">
            Server Time: {new Date().toISOString()}
          </p>
        </div>
      </div>
    </main>
  )
}
EOF


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

# Create initial admin user with proper error handling
log_info "Creating admin user..."
cat > $PROJECT_DIR/create-admin.js << ADMINEOF
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function createAdmin() {
  try {
    const hash = await bcrypt.hash(process.argv[2], 12);
    const user = await prisma.user.upsert({
      where: { username: '$ADMIN_USER' },
      update: {
        password: hash
      },
      create: {
        username: '$ADMIN_USER',
        password: hash,
        role: 'admin'
      }
    });
    console.log('Admin user created/updated successfully');
  } catch (error) {
    console.error('Error creating admin user:', error);
    process.exit(1);
  } finally {
    await prisma.\$disconnect();
  }
}

createAdmin();
ADMINEOF

cd $PROJECT_DIR && node create-admin.js "$ADMIN_PASSWORD" || log_error "Failed to create admin user"
rm $PROJECT_DIR/create-admin.js

# Install dependencies and build
log_info "Installing production dependencies..."
npm ci --production=false

log_info "Building Next.js app..."
export NODE_OPTIONS="--max-old-space-size=1536"
npm run build

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
    ssl_session_cache shared:SSL:50m;
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

    # Test and reload nginx
    log_info "Testing final Nginx configuration..."
    if nginx -t; then
        log_info "Reloading Nginx with secure configuration..."
        systemctl reload nginx
        log_info "SSL configuration applied successfully"
    else
        log_error "Nginx configuration test failed after SSL setup"
    fi
else
    log_warn "Running on HTTP only due to SSL certificate failure"
fi

# Setup automatic certificate renewal
log_info "Setting up automatic SSL certificate renewal..."
systemctl enable certbot.timer 2>/dev/null || true
systemctl start certbot.timer 2>/dev/null || true

# Create backup script
log_info "Creating backup utility..."
cat > "$PROJECT_DIR/backup.sh" << 'BACKUPEOF'
#!/bin/bash
PROJECT_NAME="PROJECT_NAME_PLACEHOLDER"
DB_TYPE="DB_TYPE_PLACEHOLDER"
BACKUP_DIR="/var/backups/$PROJECT_NAME"

mkdir -p "$BACKUP_DIR"

if [[ "$DB_TYPE" == "mariadb" ]]; then
    DB_USER="DB_USER_PLACEHOLDER"
    DB_PASSWORD="DB_PASSWORD_PLACEHOLDER"
    DB_NAME="DB_NAME_PLACEHOLDER"
    mysqldump -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" | gzip > "$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).sql.gz"
    echo "MariaDB backup created"
else
    if [[ -f "analytics.db" ]]; then
        cp analytics.db "$BACKUP_DIR/db_$(date +%Y%m%d_%H%M%S).db"
        echo "SQLite backup created"
    fi
fi

# Keep only last 7 backups
ls -t "$BACKUP_DIR"/db_* | tail -n +8 | xargs -r rm
echo "Backup completed. Location: $BACKUP_DIR"
BACKUPEOF

# Replace placeholders in backup script
sed -i "s/PROJECT_NAME_PLACEHOLDER/$PROJECT_NAME/g" "$PROJECT_DIR/backup.sh"
sed -i "s/DB_TYPE_PLACEHOLDER/$DB_TYPE/g" "$PROJECT_DIR/backup.sh"
if [[ "$DB_TYPE" == "mariadb" ]]; then
    sed -i "s/DB_USER_PLACEHOLDER/$DB_USER/g" "$PROJECT_DIR/backup.sh"
    sed -i "s/DB_PASSWORD_PLACEHOLDER/$DB_PASSWORD/g" "$PROJECT_DIR/backup.sh"
    sed -i "s/DB_NAME_PLACEHOLDER/$DB_NAME/g" "$PROJECT_DIR/backup.sh"
fi
chmod +x "$PROJECT_DIR/backup.sh"

# Create credentials file
CREDS_FILE="$PROJECT_DIR/credentials.txt"
cat > $CREDS_FILE << EOF
# Create credentials file
echo "========================================"
echo "SETUP COMPLETE"
echo "========================================"
echo ""
echo "Domain: https://$DOMAIN"
echo "Admin Dashboard: https://$DOMAIN/admin"
echo ""
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASSWORD"
echo ""
echo "Database: $DB_TYPE"
echo ""

if [[ "$DB_TYPE" == "mariadb" ]]; then
    echo "Database Details:"
    echo "  Database Name: $DB_NAME"
    echo "  Database User: $DB_USER"
    echo "  Database Password: $DB_PASSWORD"
    echo "  Database Host: $DB_HOST"
    echo "  Database Port: $DB_PORT"
    echo ""
    echo "MySQL Command Line Access:"
    echo "  mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME"
    echo ""
fi

cat > $CREDS_FILE << EOF
========================================
NEXT.JS APPLICATION CREDENTIALS
========================================

DOMAIN INFORMATION:
  Primary URL: https://$DOMAIN
  Admin Dashboard: https://$DOMAIN/admin
  Info Page: https://$DOMAIN/info

ADMIN CREDENTIALS:
  Username: $ADMIN_USER
  Password: $ADMIN_PASSWORD

DATABASE INFORMATION:
  Type: $DB_TYPE
EOF

if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
  Database Name: $DB_NAME
  Database User: $DB_USER
  Database Password: $DB_PASSWORD
  Database Host: $DB_HOST
  Database Port: $DB_PORT
  
  MySQL CLI Access:
    mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME
  
  MySQL Root Access:
    sudo mysql
  
  Create Database Backup:
    mysqldump -u $DB_USER -p'$DB_PASSWORD' $DB_NAME > backup.sql
EOF
else
    cat >> $CREDS_FILE << EOF
  Database File: $PROJECT_DIR/analytics.db
  
  SQLite CLI Access:
    sqlite3 $PROJECT_DIR/analytics.db
EOF
fi

cat >> $CREDS_FILE << EOF

APPLICATION DETAILS:
  Project Name: $PROJECT_NAME
  Project Directory: $PROJECT_DIR
  Service Name: $PROJECT_NAME
  Application Port: $APP_PORT
  Node Environment: production

API ENDPOINTS:
  Health Check:
    GET https://$DOMAIN/api/health
  
  Example Endpoints:
    GET  https://$DOMAIN/api/example
    POST https://$DOMAIN/api/example
  
  Authentication:
    POST https://$DOMAIN/api/auth/login
    Body: {"username": "$ADMIN_USER", "password": "$ADMIN_PASSWORD"}
  
  Analytics (requires auth token):
    GET https://$DOMAIN/api/analytics/summary?days=7
    GET https://$DOMAIN/api/analytics/detailed?days=7&page=1&limit=50
    GET https://$DOMAIN/api/analytics/traffic?days=7

SYSTEM COMMANDS:
  View Application Logs:
    journalctl -u $PROJECT_NAME -f
    journalctl -u $PROJECT_NAME -n 100 --no-pager
  
  Restart Application:
    sudo systemctl restart $PROJECT_NAME
  
  Stop Application:
    sudo systemctl stop $PROJECT_NAME
  
  Start Application:
    sudo systemctl start $PROJECT_NAME
  
  Check Application Status:
    sudo systemctl status $PROJECT_NAME
  
  View Nginx Access Logs:
    tail -f /var/log/nginx/$DOMAIN.access.log
  
  View Nginx Error Logs:
    tail -f /var/log/nginx/$DOMAIN.error.log
  
  Test Nginx Configuration:
    sudo nginx -t
  
  Reload Nginx:
    sudo systemctl reload nginx
  
  SSL Certificate Management:
    certbot certificates
    certbot renew --dry-run
    certbot renew
  
  Create Database Backup:
    $PROJECT_DIR/backup.sh
  
  View Backups:
    ls -lh /var/backups/$PROJECT_NAME/

SECURITY FEATURES:
  ✓ TLS 1.2/1.3 with strong ciphers
  ✓ HSTS with preload
  ✓ Security headers (X-Frame-Options, CSP, X-Content-Type-Options)
  ✓ OCSP stapling
  ✓ Automatic SSL certificate renewal (certbot.timer)
  ✓ Request/response analytics tracking
  ✓ Bandwidth monitoring
  ✓ JWT-based admin authentication (7-day token expiry)
  ✓ Password hashing with bcrypt (12 rounds)
  ✓ Rate limiting:
      - API endpoints: 10 requests/second (burst: 5)
      - General pages: 100 requests/second (burst: 20)
  ✓ Gzip compression enabled
  ✓ Health check endpoint
  ✓ Automated backup script
  ✓ Environment variable protection (.env not in git)

FILE LOCATIONS:
  Project Root: $PROJECT_DIR
  Environment Config: $PROJECT_DIR/.env
  Database Schema: $PROJECT_DIR/prisma/schema.prisma
  Nginx Config: /etc/nginx/sites-available/$DOMAIN
  SSL Certificates: /etc/letsencrypt/live/$DOMAIN/
  Systemd Service: /etc/systemd/system/$PROJECT_NAME.service
  Backup Script: $PROJECT_DIR/backup.sh
  Backups Directory: /var/backups/$PROJECT_NAME/
  This File: $CREDS_FILE

TESTING COMMANDS:
  Test Homepage:
    curl -I https://$DOMAIN
  
  Test Health Endpoint:
    curl https://$DOMAIN/api/health
  
  Test API Endpoint:
    curl https://$DOMAIN/api/example
  
  Test Admin Login:
    curl -X POST https://$DOMAIN/api/auth/login \\
      -H "Content-Type: application/json" \\
      -d '{"username":"$ADMIN_USER","password":"$ADMIN_PASSWORD"}'
  
  Test Analytics (replace TOKEN):
    curl https://$DOMAIN/api/analytics/summary?days=7 \\
      -H "Authorization: Bearer TOKEN"

TROUBLESHOOTING:
  Application won't start:
    - Check logs: journalctl -u $PROJECT_NAME -n 50
    - Check port: lsof -i :$APP_PORT
    - Check permissions: ls -la $PROJECT_DIR
  
  Database connection issues:
EOF

if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
    - Test connection: mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME -e "SELECT 1;"
    - Check MariaDB status: systemctl status mariadb
    - View MariaDB logs: journalctl -u mariadb -n 50
EOF
else
    cat >> $CREDS_FILE << EOF
    - Check file exists: ls -la $PROJECT_DIR/analytics.db
    - Check permissions: ls -la $PROJECT_DIR/analytics.db
EOF
fi

cat >> $CREDS_FILE << EOF
  
  SSL certificate issues:
    - Verify DNS: dig $DOMAIN
    - Check firewall: ufw status
    - Manual renewal: certbot renew --force-renewal
  
  Nginx issues:
    - Test config: nginx -t
    - Check syntax: nginx -T
    - View error log: tail -f /var/log/nginx/error.log

MAINTENANCE TASKS:
  Daily:
    - Monitor logs: journalctl -u $PROJECT_NAME --since today
  
  Weekly:
    - Run backup: $PROJECT_DIR/backup.sh
    - Check disk space: df -h
    - Review analytics: https://$DOMAIN/admin
  
  Monthly:
    - Update packages: apt update && apt upgrade
    - Clean old logs: journalctl --vacuum-time=30d
    - Review SSL cert expiry: certbot certificates

IMPORTANT NOTES:
  ⚠ SAVE THIS FILE SECURELY - It contains sensitive credentials
  ⚠ The .env file contains secrets - never commit it to git
  ⚠ Admin password is auto-generated - change it from the dashboard
  ⚠ Database backups are kept for 7 days only
  ⚠ SSL certificates auto-renew via certbot.timer

========================================
Setup completed: $(date)
========================================
EOF

chmod 600 $CREDS_FILE

# Display final status
echo ""
echo "=========================================="
log_info "🎉 Setup completed successfully!"
echo "=========================================="
echo ""
cat $CREDS_FILE
echo ""
echo "📄 Full credentials saved to: $CREDS_FILE"
echo ""

if [[ "$AUTO_GENERATED_PASS" == true ]]; then
    log_warn "⚠️  Admin password was auto-generated. Please save it securely!"
fi

if [ "$SSL_SUCCESS" = true ]; then
    echo "🌐 Your Next.js app is now live at: https://$DOMAIN"
    echo "🔐 SSL certificate installed and configured"
else
    echo "🌐 Your Next.js app is running at: http://$DOMAIN"
    log_warn "SSL setup failed. You can manually configure it later with: certbot --nginx -d $DOMAIN"
fi

echo ""
echo "=========================================="
log_info "📋 Quick Start:"
echo "  1. Visit: https://$DOMAIN"
echo "  2. Admin: https://$DOMAIN/admin"
echo "  3. Login: $ADMIN_USER / $ADMIN_PASSWORD"
echo "  4. Test: curl https://$DOMAIN/api/health"
echo "=========================================="
echo ""
log_info "📚 Post-installation recommendations:"
echo "  1. Run a backup: $PROJECT_DIR/backup.sh"
echo "  2. Check health: curl https://$DOMAIN/api/health"
echo "  3. Monitor logs: journalctl -u $PROJECT_NAME -f"
echo "  4. Review credentials: cat $CREDS_FILE"
echo "=========================================="


if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
  Database: $DB_NAME
  User: $DB_USER
  Password: $DB_PASSWORD
  Host: $DB_HOST
  Port: $DB_PORT
  Connection: mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME
EOF
else
    cat >> $CREDS_FILE << EOF
  Database File: $PROJECT_DIR/analytics.db
EOF
fi

cat >> $CREDS_FILE << EOF

Project Directory: $PROJECT_DIR
Service Name: $PROJECT_NAME
Application Port: $APP_PORT

API Endpoints:
  - GET  /api/health - Health check endpoint
  - GET  /api/example - Example API endpoint
  - POST /api/example - Example POST endpoint
  - POST /api/auth/login - Admin login
  - GET  /api/analytics/summary - Analytics summary
  - GET  /api/analytics/detailed - Detailed analytics
  - GET  /api/analytics/traffic - Traffic stats

Useful Commands:
  - View app logs: journalctl -u $PROJECT_NAME -f
  - Restart app: systemctl restart $PROJECT_NAME
  - Check status: systemctl status $PROJECT_NAME
  - Nginx logs: tail -f /var/log/nginx/$DOMAIN.access.log
  - SSL test: certbot certificates
  - Renew SSL: certbot renew
  - Create backup: $PROJECT_DIR/backup.sh
EOF

if [[ "$DB_TYPE" == "mariadb" ]]; then
    cat >> $CREDS_FILE << EOF
  - Database console: mysql -u $DB_USER -p'$DB_PASSWORD' $DB_NAME
EOF
fi

cat >> $CREDS_FILE << EOF

Security Features Enabled:
  ✓ TLS 1.2/1.3 with strong ciphers
  ✓ HSTS with preload
  ✓ Security headers (X-Frame-Options, CSP, etc.)
  ✓ OCSP stapling
  ✓ Automatic certificate renewal
  ✓ Request/response analytics tracking
  ✓ Bandwidth monitoring
  ✓ JWT-based admin authentication
  ✓ Rate limiting (API: 10req/s, General: 100req/s)
  ✓ Gzip compression
  ✓ Health check endpoint
  ✓ Automated backup script

========================================
IMPORTANT: Save these credentials securely!
========================================
EOF

chmod 600 $CREDS_FILE

# Display final status
echo ""
echo "=========================================="
log_info "🎉 Setup completed successfully!"
echo "=========================================="
echo ""
cat $CREDS_FILE
echo ""
echo "Credentials saved to: $CREDS_FILE"
echo ""

if [[ "$AUTO_GENERATED_PASS" == true ]]; then
    log_warn "Admin password was auto-generated. Please save it securely!"
fi

if [ "$SSL_SUCCESS" = true ]; then
    echo "Your Next.js app is now live at: https://$DOMAIN"
else
    echo "Your Next.js app is running at: http://$DOMAIN"
    log_warn "SSL setup failed. You can manually configure it later with: certbot --nginx -d $DOMAIN"
fi

echo "=========================================="
log_info "Post-installation recommendations:"
echo "  1. Run a backup: $PROJECT_DIR/backup.sh"
echo "  2. Test your site: curl -I https://$DOMAIN"
echo "  3. Check health: curl https://$DOMAIN/api/health"
echo "  4. Monitor logs: journalctl -u $PROJECT_NAME -f"
echo "=========================================="
