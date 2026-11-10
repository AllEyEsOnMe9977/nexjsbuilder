# =============================================================================
# 04d-app-api.sh
# All app/api/* route handlers: health, auth/login, analytics endpoints, example
# Sourced by 04-app.sh — expects log_info() defined. Must run after
# 04a-app-init.sh (needs project dir) and 04b-app-env.sh (needs lib/db, lib/auth,
# lib/analytics).
# =============================================================================

# Create API routes directory structure
log_info "Creating API directory structure..."
mkdir -p app/api/auth/login
mkdir -p app/api/auth/logout
mkdir -p app/api/analytics/summary
mkdir -p app/api/analytics/detailed
mkdir -p app/api/analytics/traffic
mkdir -p app/api/analytics/track
mkdir -p app/api/health
mkdir -p app/api/example

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
      uptime: process.uptime(),
    })
  } catch (error) {
    console.error('Health check failed:', error)
    return NextResponse.json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error instanceof Error ? error.message : 'Unknown error',
    }, { status: 503 })
  }
}
EOF

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

    const user = await prisma.user.findUnique({ where: { username } })
    if (!user || !(await verifyPassword(password, user.password))) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
    }

    const token = generateToken(user.id, user.username)
    const response = NextResponse.json({ username: user.username, token })

    response.cookies.set('adminToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 60 * 60 * 24 * 7,
    })

    return response
  } catch (error) {
    console.error('Login error:', error)
    return NextResponse.json({
      error: 'Login failed',
      details: error instanceof Error ? error.message : 'Unknown error',
    }, { status: 500 })
  }
}
EOF

cat > app/api/auth/logout/route.ts << 'EOF'
import { NextResponse } from 'next/server'

export const runtime = 'nodejs'

export async function POST() {
  const response = NextResponse.json({ success: true })
  response.cookies.set('adminToken', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 0,
  })
  return response
}
EOF

cat > app/api/analytics/summary/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'
import { getAnalyticsSummary } from '@/lib/analytics'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

function getToken(req: NextRequest): string | null {
  const cookieToken = req.cookies.get('adminToken')?.value
  if (cookieToken) return cookieToken
  const auth = req.headers.get('authorization')
  return auth?.startsWith('Bearer ') ? auth.slice(7) : null
}

export async function GET(request: NextRequest) {
  try {
    const token = getToken(request)
    if (!token || !verifyToken(token)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const rawDays = parseInt(searchParams.get('days') || '7', 10)
    const days = Number.isFinite(rawDays) ? Math.min(Math.max(rawDays, 1), 365) : 7

    const summary = await getAnalyticsSummary(days)
    return NextResponse.json(summary, {
      headers: { 'Cache-Control': 'no-store, max-age=0' },
    })
  } catch (error) {
    console.error('Analytics summary error:', error)
    return NextResponse.json({ error: 'Failed to fetch analytics' }, { status: 500 })
  }
}
EOF

cat > app/api/analytics/detailed/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'
import { prisma } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

function getToken(req: NextRequest): string | null {
  const cookieToken = req.cookies.get('adminToken')?.value
  if (cookieToken) return cookieToken
  const auth = req.headers.get('authorization')
  return auth?.startsWith('Bearer ') ? auth.slice(7) : null
}

export async function GET(request: NextRequest) {
  try {
    const token = getToken(request)
    if (!token || !verifyToken(token)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const rawDays = parseInt(searchParams.get('days') || '7', 10)
    const rawPage = parseInt(searchParams.get('page') || '1', 10)
    const rawLimit = parseInt(searchParams.get('limit') || '50', 10)

    const days = Number.isFinite(rawDays) ? Math.min(Math.max(rawDays, 1), 365) : 7
    const page = Number.isFinite(rawPage) ? Math.max(rawPage, 1) : 1
    const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(rawLimit, 1), 200) : 50

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
      headers: { 'Cache-Control': 'no-store, max-age=0' },
    })
  } catch (error) {
    console.error('Detailed analytics error:', error)
    return NextResponse.json({ error: 'Failed to fetch detailed analytics' }, { status: 500 })
  }
}
EOF

cat > app/api/analytics/traffic/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'
import { prisma } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

function getToken(req: NextRequest): string | null {
  const cookieToken = req.cookies.get('adminToken')?.value
  if (cookieToken) return cookieToken
  const auth = req.headers.get('authorization')
  return auth?.startsWith('Bearer ') ? auth.slice(7) : null
}

export async function GET(request: NextRequest) {
  try {
    const token = getToken(request)
    if (!token || !verifyToken(token)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const rawDays = parseInt(searchParams.get('days') || '7', 10)
    const days = Number.isFinite(rawDays) ? Math.min(Math.max(rawDays, 1), 365) : 7

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
      headers: { 'Cache-Control': 'no-store, max-age=0' },
    })
  } catch (error) {
    console.error('Traffic stats error:', error)
    return NextResponse.json({ error: 'Failed to fetch traffic stats' }, { status: 500 })
  }
}
EOF

cat > app/api/example/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'

export async function GET() {
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
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 })
  }
}
EOF

cat > app/api/analytics/track/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { logAnalytics } from '@/lib/analytics'

export const runtime = 'nodejs'

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text()
    const body = JSON.parse(rawBody)
    const { path } = body

    if (typeof path !== 'string' || path.length > 500) {
      return NextResponse.json({ success: false }, { status: 400 })
    }

    const forwardedFor = request.headers.get('x-forwarded-for')
    const realIp = request.headers.get('x-real-ip')
    let ip = '127.0.0.1'

    if (forwardedFor) {
      ip = forwardedFor.split(',')[0].trim()
    } else if (realIp) {
      ip = realIp.trim()
    }

    if (ip.startsWith('::ffff:')) {
      ip = ip.substring(7)
    }

    await logAnalytics({
      ip,
      userAgent: request.headers.get('user-agent') || undefined,
      method: 'GET',
      path: path || '/',
      statusCode: 200,
      responseTime: 0,
      referer: request.headers.get('referer') || undefined,
      bytesIn: Buffer.byteLength(rawBody, 'utf8'),
      bytesOut: 20,
    })

    return NextResponse.json({ success: true })
  } catch {
    return NextResponse.json({ success: false }, { status: 500 })
  }
}
EOF