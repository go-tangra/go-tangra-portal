import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useSession } from '@/stores/session'

function mockFetch(status: number, body: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })),
  )
}

describe('session store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('becomes authenticated from /gateway/v1/me', async () => {
    mockFetch(200, { user_id: 'u1', tenant_id: 't1', roles: ['admin'], operator: true })
    const s = useSession()
    await s.load()
    expect(s.signedIn).toBe(true)
    expect(s.operator).toBe(true)
    expect(s.hasAnyRole(['owner', 'admin'])).toBe(true)
    expect(s.hasRole('auditor')).toBe(false)
  })

  it('keeps display name and avatar, derives initials, and refreshes on demand', async () => {
    mockFetch(200, { user_id: 'u1', tenant_id: 't1', roles: [], display_name: 'Dana Kovač', avatar_url: '/api/v1/users/u1/avatar/abc' })
    const s = useSession()
    await s.load()
    expect(s.displayName).toBe('Dana Kovač')
    expect(s.avatarUrl).toBe('/api/v1/users/u1/avatar/abc')
    expect(s.initials).toBe('DK')
    mockFetch(200, { user_id: 'u1', tenant_id: 't1', roles: [], display_name: 'D. Kovač', avatar_url: '' })
    await s.refresh()
    expect(s.displayName).toBe('D. Kovač')
    expect(s.avatarUrl).toBe('')
    s.reset()
    expect(s.displayName).toBe('')
  })

  it('is anonymous on 401 and shares one in-flight request', async () => {
    mockFetch(401, { reason: 'unauthenticated' })
    const s = useSession()
    await Promise.all([s.load(), s.load()])
    expect(s.status).toBe('anonymous')
    expect(vi.mocked(fetch).mock.calls.length).toBe(1)
  })

  it('reports an outage on network failure and 5xx', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline') }))
    const s = useSession()
    await s.load()
    expect(s.status).toBe('outage')
    mockFetch(503, {})
    await s.load(true)
    expect(s.status).toBe('outage')
  })

  it('orders navigation across modules', async () => {
    mockFetch(200, [
      { module: 'billing', nav: [{ title: 'Invoices', path: '/billing', order: 20 }] },
      { module: 'orders', nav: [{ title: 'Orders', path: '/orders', order: 10 }, { title: 'Archive', path: '/orders/archive', order: 10 }] },
    ])
    const s = useSession()
    await s.loadModules()
    expect(s.nav.map((n) => n.title)).toEqual(['Archive', 'Orders', 'Invoices'])
  })

  it('signs out through the auth module with the CSRF header and resets', async () => {
    document.cookie = '__Host-csrf=tok123; Secure; Path=/'
    mockFetch(204, {})
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1' })
    await s.signOut()
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/signout')
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok123')
    expect(s.status).toBe('anonymous')
  })

  it('resets on session loss events', () => {
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1' })
    const unbind = s.bindEvents()
    s.reset()
    expect(s.status).toBe('anonymous')
    unbind()
  })
})
