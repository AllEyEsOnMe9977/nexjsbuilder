# =============================================================================
# 04b-app-env.sh
# Environment config (.env), .gitignore, and lib/ utilities (db, auth, analytics)
# Sourced by 04-app.sh — expects DB_TYPE, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT,
# DB_NAME, ADMIN_USER, DOMAIN, APP_PORT, generate_password(), log_info() to be
# defined by earlier modules. Must run after 04a-app-init.sh (needs project dir).
# =============================================================================

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