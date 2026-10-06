import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createApi } from '@go-tangra/ui/api'
import { ApiError } from '@/api/client'
import { createKeeper, REFRESH_EVERY, STORAGE_KEY, WARN_BEFORE, type Refresh } from '@/session/keeper'
import { checkSession, resetExpiryForTests, watchSessionExpiry } from '@/session/expiry'
import { navigation } from '@/router'
import { useSession } from '@/stores/session'

const IDLE = 60 * 60_000

function memoryStorage() {
  const m = new Map<string, string>()
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), m }
}

function harness(over: { refresh?: () => Promise<Refresh> } = {}) {
  let now = Date.parse('2026-10-06T08:00:00Z')
  const listeners = new Map<string, () => void>()
  const target = { addEventListener: (t: string, fn: () => void) => void listeners.set(t, fn), removeEventListener: (t: string) => void listeners.delete(t) }
  const storage = memoryStorage()
  const refresh = vi.fn(over.refresh ?? (async (): Promise<Refresh> => ({ session_id: 's1', expires_at: new Date(now + 8 * 3600_000).toISOString(), idle_timeout_seconds: IDLE / 1000, renewed: true })))
  const expire = vi.fn()
  const keeper = createKeeper({ now: () => now, refresh, expire, storage, target, setInterval: () => 1, clearInterval: () => undefined })
  return {
    keeper, refresh, expire, storage, listeners,
    advance: async (ms: number) => { now += ms; keeper.tick(); await Promise.resolve(); await Promise.resolve() },
    act: () => listeners.get('pointerdown')?.(),
    now: () => now,
  }
}

describe('session keeper', () => {
  it('renews at start and shares the deadlines with the other tabs', async () => {
    const h = harness()
    h.keeper.start()
    await Promise.resolve()
    expect(h.refresh).toHaveBeenCalledTimes(1)
    const shared = JSON.parse(h.storage.m.get(STORAGE_KEY)!)
    expect(shared.idle).toBe(h.now() + IDLE)
    expect(h.keeper.state.running).toBe(true)
  })

  it('renews only while the person is active, at most every REFRESH_EVERY', async () => {
    const h = harness()
    h.keeper.start()
    await Promise.resolve()
    await h.advance(REFRESH_EVERY) // no activity: no renewal
    expect(h.refresh).toHaveBeenCalledTimes(1)
    h.act()
    await h.advance(1000)
    expect(h.refresh).toHaveBeenCalledTimes(2)
    h.act()
    await h.advance(60_000) // active again, but renewed a minute ago
    expect(h.refresh).toHaveBeenCalledTimes(2)
  })

  it('warns WARN_BEFORE the idle deadline; acting during the warning keeps the session', async () => {
    const h = harness()
    h.keeper.start()
    await Promise.resolve()
    await h.advance(IDLE - WARN_BEFORE - 1000)
    expect(h.keeper.state.warning).toBe(false)
    await h.advance(1000)
    expect(h.keeper.state.warning).toBe(true)
    expect(h.keeper.state.secondsLeft).toBe(WARN_BEFORE / 1000)
    h.act() // any activity counts as "stay signed in"
    await Promise.resolve()
    await Promise.resolve()
    expect(h.refresh).toHaveBeenCalledTimes(2)
    expect(h.keeper.state.warning).toBe(false)
    await h.advance(1000)
    expect(h.keeper.state.warning).toBe(false)
    expect(h.expire).not.toHaveBeenCalled()
  })

  it('ends an unattended session once at the deadline and stops', async () => {
    const h = harness()
    h.keeper.start()
    await Promise.resolve()
    await h.advance(IDLE)
    expect(h.expire).toHaveBeenCalledTimes(1)
    expect(h.keeper.state.running).toBe(false)
    expect(h.keeper.state.warning).toBe(false)
    await h.advance(1000)
    expect(h.expire).toHaveBeenCalledTimes(1)
  })

  it('another tab\'s renewal moves the deadline: no warning, no expiry here', async () => {
    const h = harness()
    h.keeper.start()
    await Promise.resolve()
    await h.advance(IDLE - 30_000)
    expect(h.keeper.state.warning).toBe(true)
    // The other tab renewed just now.
    h.storage.setItem(STORAGE_KEY, JSON.stringify({ idle: h.now() + IDLE, expires: h.now() + 8 * 3600_000, at: h.now() }))
    await h.advance(1000)
    expect(h.keeper.state.warning).toBe(false)
    await h.advance(40_000)
    expect(h.expire).not.toHaveBeenCalled()
  })

  it('"Stay signed in" renews; a refused renewal leaves the 401 to the expiry watcher', async () => {
    const h = harness({ refresh: async () => { throw new ApiError(401, 'unauthenticated') } })
    h.keeper.start()
    await expect(h.keeper.stay()).resolves.toBeUndefined()
    expect(h.refresh).toHaveBeenCalled()
    expect(h.expire).not.toHaveBeenCalled()
  })
})

describe('session expiry watcher', () => {
  let assigned: string[] = []
  beforeEach(() => {
    setActivePinia(createPinia())
    resetExpiryForTests()
    assigned = []
    vi.spyOn(navigation, 'assign').mockImplementation((u: string) => void assigned.push(u))
    window.history.replaceState(null, '', '/warden/secrets?folder=f1')
  })
  const respond = (byPath: Record<string, number>) =>
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const status = byPath[new URL(url, 'https://x').pathname] ?? 200
      const body = status === 200 ? { user_id: 'u1', tenant_id: 't1' } : { reason: 'unauthenticated' }
      return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
    }))

  it('a module\'s 401 with the session gone sends the person to sign-in, back to the same page', async () => {
    respond({})
    const session = useSession()
    await session.load()
    const off = watchSessionExpiry()
    respond({ '/api/warden/v1/secrets': 401, '/gateway/v1/me': 401 })
    await expect(createApi({ base: '/api/warden/v1' })('GET', 'secrets')).rejects.toMatchObject({ status: 401 })
    await vi.waitFor(() => expect(assigned).toEqual(['/console/signin?next=' + encodeURIComponent('/warden/secrets?folder=f1')]))
    off()
  })

  it('a 401 while the session is still alive (a module\'s own refusal) does not sign anyone out', async () => {
    respond({})
    const session = useSession()
    await session.load()
    const off = watchSessionExpiry()
    respond({ '/api/warden/v1/secrets': 401 })
    await expect(createApi({ base: '/api/warden/v1' })('GET', 'secrets')).rejects.toMatchObject({ status: 401 })
    await checkSession()
    expect(assigned).toEqual([])
    expect(session.signedIn).toBe(true)
    off()
  })

  it('does nothing for an anonymous browser (sign-in pages)', async () => {
    respond({ '/gateway/v1/me': 401 })
    await useSession().load()
    await checkSession()
    expect(assigned).toEqual([])
  })
})
