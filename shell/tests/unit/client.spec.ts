import { describe, expect, it, vi } from 'vitest'
import { api, ApiError, csrfToken, onApiEvent } from '@/api/client'

describe('api client', () => {
  it('sends the CSRF header on state-changing calls and maps reasons', async () => {
    document.cookie = '__Host-csrf=tok123; Secure; Path=/'
    expect(csrfToken()).toBe('tok123')
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ reason: 'forbidden' }), { status: 403 })))
    await expect(api('POST', '/gateway/v1/ops/registrations/orders/drain')).rejects.toMatchObject({ status: 403, reason: 'forbidden' })
    const init = vi.mocked(fetch).mock.calls[0]?.[1] as RequestInit
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok123')
    expect(init.credentials).toBe('same-origin')
  })

  it('raises outage on 5xx and network errors, recovered on success', async () => {
    const events: string[] = []
    const off = onApiEvent((e) => events.push(e))
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 503 })))
    await expect(api('GET', '/gateway/v1/me')).rejects.toBeInstanceOf(ApiError)
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline') }))
    await expect(api('GET', '/gateway/v1/me')).rejects.toMatchObject({ status: 0, reason: 'network' })
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ user_id: 'u' }), { status: 200 })))
    expect(await api<{ user_id: string }>('GET', '/gateway/v1/me')).toEqual({ user_id: 'u' })
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 401 })))
    await expect(api('GET', '/gateway/v1/me')).rejects.toMatchObject({ status: 401 })
    off()
    expect(events).toEqual(['outage', 'outage', 'recovered', 'recovered', 'unauthenticated'])
  })

  it('appends query parameters and returns undefined on 204', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 204 })))
    expect(await api('GET', '/gateway/v1/ops/audit', undefined, { query: { module: 'orders', cursor: undefined } })).toBeUndefined()
    expect(vi.mocked(fetch).mock.calls[0]?.[0]).toBe('/gateway/v1/ops/audit?module=orders')
  })
})
