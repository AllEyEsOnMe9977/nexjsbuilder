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

  // 3. Ignore requests from localhost to prevent internal loops
  const forwardedFor = request.headers.get('x-forwarded-for')
  const realIp = request.headers.get('x-real-ip')
  if (forwardedFor?.includes('127.0.0.1') || realIp === '127.0.0.1') {
    return response
  }

  const startTime = Date.now()
 
  // Prepare payload
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

  // Send to internal API using LOCALHOST explicitly
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
      signal: AbortSignal.timeout(5000), 
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

# Create info page
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