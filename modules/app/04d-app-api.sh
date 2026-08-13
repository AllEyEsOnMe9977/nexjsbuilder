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