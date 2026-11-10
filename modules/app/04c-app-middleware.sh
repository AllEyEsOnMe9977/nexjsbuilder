# =============================================================================
# 04c-app-middleware.sh
# Internal analytics recording endpoint + lightweight middleware.ts
# =============================================================================

mkdir -p app/api/analytics/record
cat > app/api/analytics/record/route.ts << 'EOF'
import { NextRequest, NextResponse } from 'next/server'
import { logAnalytics } from '@/lib/analytics'

export const runtime = 'nodejs'

export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('x-internal-secret')
    if (!process.env.JWT_SECRET || authHeader !== process.env.JWT_SECRET) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const data = await request.json()
    await logAnalytics(data)

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Analytics Record Error:', error)
    return NextResponse.json({ error: 'Internal Error' }, { status: 500 })
  }
}
EOF

# Remove legacy middleware.ts if present so Next.js 16 does not fail on duplicate conventions
rm -f middleware.ts

# Create Next.js 16 proxy.ts (replaces deprecated middleware.ts)
cat > proxy.ts << 'EOF'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

if (!process.env.PORT) {
  console.warn('[Proxy] PORT env variable not set, using default 3000')
}

export async function proxy(request: NextRequest) {
  const response = NextResponse.next()
  const pathname = request.nextUrl.pathname

  // 1. Ignore internal analytics endpoint, static assets, and Next.js prefetch/RSC sub-requests
  if (
    pathname.startsWith('/api/analytics/record') ||
    pathname.startsWith('/_next') ||
    pathname.includes('.') ||
    pathname.startsWith('/favicon.ico') ||
    request.headers.get('purpose') === 'prefetch' ||
    request.headers.get('next-router-prefetch') ||
    request.headers.get('rsc') === '1'
  ) {
    return response
  }

  // 2. Ignore internal loopback requests
  const forwardedFor = request.headers.get('x-forwarded-for')
  const realIp = request.headers.get('x-real-ip')
  if (forwardedFor?.includes('127.0.0.1') || realIp === '127.0.0.1') {
    return response
  }

  const startTime = Date.now()
  const ip =
    forwardedFor?.split(',')[0].trim() ||
    realIp ||
    '127.0.0.1'

  const analyticsPayload = {
    ip,
    userAgent: request.headers.get('user-agent'),
    method: request.method,
    path: pathname,
    statusCode: 200,
    responseTime: Date.now() - startTime,
    referer: request.headers.get('referer'),
  }

  const port = process.env.PORT || '3000'
  const internalApiUrl = `http://localhost:${port}/api/analytics/record`

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
      console.error(`[Proxy] Analytics request failed: ${err.message}`)
    })
  } catch {
    // Do not block incoming requests on analytics errors
  }

  return response
}

export const config = {
  matcher: [
    '/((?!api/|_next/static|_next/image|favicon.ico).*)',
  ],
}
EOF