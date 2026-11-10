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

cat > middleware.ts << 'EOF'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(_request: NextRequest) {
  return NextResponse.next()
}

export const config = {
  matcher: [
    '/((?!api/|_next/static|_next/image|favicon.ico).*)',
  ],
}
EOF