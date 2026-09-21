import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createShellRouter, navigation, SIGNIN_PATH } from '@/router'
import { useSession } from '@/stores/session'

describe('shell router guards', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('sends anonymous browsers to the auth module sign-in', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 401 })))
    const assign = vi.spyOn(navigation, 'assign').mockImplementation(() => undefined)
    const router = createShellRouter()
    await router.push('/ops').catch(() => undefined)
    expect(assign).toHaveBeenCalledWith(SIGNIN_PATH + '?next=' + encodeURIComponent('/ops'))
    // Module paths are unknown until the modules compose after sign-in.
    await router.push('/hello/x').catch(() => undefined)
    expect(assign).toHaveBeenLastCalledWith(SIGNIN_PATH + '?next=' + encodeURIComponent('/hello/x'))
  })

  it('never redirects the sign-in page into itself (no next-nesting loop)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 401 })))
    const assign = vi.spyOn(navigation, 'assign').mockImplementation(() => undefined)
    const router = createShellRouter()
    // The gateway served the shell for /console/signin (auth unreachable): the
    // catch-all matches it, but the guard must not wrap it in another next.
    await router.push(SIGNIN_PATH).catch(() => undefined)
    await router.push(SIGNIN_PATH + '?next=' + encodeURIComponent('/ops')).catch(() => undefined)
    expect(assign).not.toHaveBeenCalled()
  })

  it('routes outage and forbidden', async () => {
    const s = useSession()
    s.status = 'outage'
    const router = createShellRouter()
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('outage')
    s.apply({ user_id: 'u', tenant_id: 't', operator: false })
    await router.push('/ops')
    expect(router.currentRoute.value.name).toBe('forbidden')
    s.operator = true
    await router.push('/ops')
    expect(router.currentRoute.value.name).toBe('ops')
  })
})
