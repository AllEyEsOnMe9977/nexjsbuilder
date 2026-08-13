# =============================================================================
# 04c-app-middleware.sh
# Internal analytics recording endpoint (bridge for middleware) + middleware.ts
# Sourced by 04-app.sh — must run after 04a-app-init.sh (needs project dir).
# =============================================================================

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