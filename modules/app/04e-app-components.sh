# =============================================================================
# 04e-app-components.sh
# React components: ClientAnalytics tracker, admin dashboard, info page
# Sourced by 04-app.sh — must run after 04a-app-init.sh (needs project dir).
# =============================================================================

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
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [checkingSession, setCheckingSession] = useState(true)
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null)
  const [days, setDays] = useState(7)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // The JWT lives in an httpOnly cookie set by the server, so the browser
  // attaches it automatically - there is no token in JS to manage here.
  const fetchAnalytics = useCallback(async (daysParam: number) => {
    setLoading(true)
    setError('')
   
    try {
      const res = await fetch(`/api/analytics/summary?days=${daysParam}`, {
        credentials: 'include',
        headers: { 'Cache-Control': 'no-cache' },
      })

      if (res.ok) {
        const data = await res.json()
        setAnalytics(data)
        setIsLoggedIn(true)
      } else if (res.status === 401) {
        setIsLoggedIn(false)
        setAnalytics(null)
      } else {
        setError('Failed to load data')
      }
    } catch (err) {
      setError('Connection error')
    } finally {
      setLoading(false)
      setCheckingSession(false)
    }
  }, [])

  // On mount, ask the server if we have a valid session cookie - this
  // replaces the old "read token from localStorage" check.
  useEffect(() => {
    fetchAnalytics(days)
  }, [days, fetchAnalytics])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      if (res.ok) {
        setIsLoggedIn(true)
        fetchAnalytics(days)
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

  const handleLogout = async () => {
    try {
      // httpOnly cookies can't be cleared from JS - the server must do it.
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })
    } catch (err) {
      // Even if the request fails, drop client-side state below.
    }
    setIsLoggedIn(false)
    setAnalytics(null)
  }

  if (checkingSession) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <p className="text-gray-600">Loading...</p>
      </div>
    )
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