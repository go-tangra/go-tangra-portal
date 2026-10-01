import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import Registrations from '@/views/ops/Registrations.vue'
import Allowlist from '@/views/ops/Allowlist.vue'
import Audit from '@/views/ops/Audit.vue'

type Call = { url: string; init: RequestInit }
function fetchMock(handler: (url: string, init: RequestInit) => unknown): Call[] {
  const calls: Call[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init })
    const body = handler(url, init)
    if (body === 204) return new Response(null, { status: 204 })
    if (typeof body === 'object' && body !== null && 'status' in (body as object)) return new Response(JSON.stringify((body as { body: unknown }).body), { status: (body as { status: number }).status })
    return new Response(JSON.stringify(body), { status: 200 })
  }))
  return calls
}

const page = (items: unknown[], extra: Record<string, unknown> = {}) => ({ items, total: items.length, page: 1, page_size: 25, sort: 'module', order: 'asc', ...extra })
const reg = (module: string, state: string) => ({ module, identity: 'spiffe://example.org/svc/' + module, state, instances: 1, unhealthy: 0, manifest: { version: '1.0.0' }, traffic: { requests_1m: 3, refusals_1m: 1, p95_ms: 12.34 } })

describe('operations views', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  it('lists registrations and drains/undrains with the CSRF header', async () => {
    let state = 'active'
    const calls = fetchMock((url, init) => {
      if (url.endsWith('/drain') && init.method === 'POST') {
        state = 'draining'
        return 204
      }
      if (url.endsWith('/undrain')) {
        state = 'active'
        return 204
      }
      return page([reg('alpha', state)])
    })
    const w = mount(Registrations)
    await flushPromises()
    expect(w.find('[data-test="state-alpha"]').text()).toBe('active')
    expect(w.text()).toContain('12.3')
    await w.find('[data-test="drain-alpha"]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.url.endsWith('/gateway/v1/ops/registrations/alpha/drain') && (c.init.headers as Record<string, string>)['X-CSRF-Token'] === 'tok')).toBe(true)
    expect(w.find('[data-test="state-alpha"]').text()).toBe('draining')
    await w.find('[data-test="undrain-alpha"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="state-alpha"]').text()).toBe('active')
  })

  it('requires a reason of ten characters before revoking', async () => {
    const calls = fetchMock((url) => (url.endsWith('/revoke') ? 204 : page([reg('alpha', 'active')])))
    const w = mount(Registrations, { attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="revoke-alpha"]').trigger('click')
    await flushPromises()
    const confirm = () => document.querySelector('[data-test="revoke-confirm"]') as HTMLButtonElement
    expect(confirm().disabled).toBe(true)
    const ta = document.querySelector('[data-test="revoke-reason"] textarea') as HTMLTextAreaElement
    ta.value = 'short'
    ta.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(confirm().disabled).toBe(true)
    ta.value = 'decommissioned by the platform team'
    ta.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(confirm().disabled).toBe(false)
    confirm().click()
    await flushPromises()
    const revoke = calls.find((c) => c.url.endsWith('/alpha/revoke'))
    expect(revoke).toBeTruthy()
    expect(JSON.parse(String(revoke!.init.body))).toEqual({ reason: 'decommissioned by the platform team' })
    w.unmount()
  })

  it('adds and revokes allow-list entries', async () => {
    const entries: unknown[] = []
    const calls = fetchMock((url, init) => {
      if (init.method === 'POST' && url.endsWith('/ops/allowlist')) {
        entries.push({ id: 'e1', spiffe_id: 'spiffe://example.org/svc/orders', prefixes: ['/api/orders'], names: ['orders'], created_by: 'op', created_at: 'now' })
        return { status: 201, body: entries[0] }
      }
      if (url.endsWith('/e1/revoke')) {
        entries.length = 0
        return 204
      }
      return page(entries)
    })
    const w = mount(Allowlist)
    await flushPromises()
    expect(w.find('[data-test="empty"]').exists()).toBe(false)
    await w.find('[data-test="allow-spiffe"] input').setValue('spiffe://example.org/svc/orders')
    await w.find('[data-test="allow-prefixes"] input').setValue('/api/orders, /orders-reports')
    await w.find('[data-test="allow-names"] input').setValue('orders')
    await w.find('[data-test="allow-form"]').trigger('submit')
    await flushPromises()
    const add = calls.find((c) => c.init.method === 'POST' && c.url.endsWith('/ops/allowlist'))
    expect(JSON.parse(String(add!.init.body))).toEqual({ spiffe_id: 'spiffe://example.org/svc/orders', prefixes: ['/api/orders', '/orders-reports'], names: ['orders'] })
    expect(w.find('[data-test="allow-e1"]').exists()).toBe(true)
    await w.find('[data-test="allow-revoke-e1"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="allow-e1"]').exists()).toBe(false)
  })

  it('renders the audit trail as server pages: pager, header sort, filters back to page 1', async () => {
    const ev = (i: number) => ({ id: i, ts: 't' + i, event_type: 'module_drained', module: 'alpha', actor_kind: 'operator', actor_id: 'op', subject_kind: 'module', subject_id: 'alpha', outcome: 'ok', reason: 'drained', correlation_id: '', details: {} })
    const calls = fetchMock((url) => {
      const q = new URL(url, 'https://x').searchParams
      const p = Number(q.get('page') ?? 1)
      return { items: [ev(p)], total: 120, page: p, page_size: Number(q.get('page_size')), sort: q.get('sort'), order: q.get('order') }
    })
    const w = mount(Audit)
    await flushPromises()
    const last = () => new URL(calls.at(-1)!.url, 'https://x').searchParams
    expect(last().get('page')).toBe('1')
    expect(last().get('page_size')).toBe('50')
    expect(last().get('sort')).toBe('ts')
    expect(last().get('order')).toBe('desc')
    expect(last().get('cursor')).toBeNull()
    expect(w.text()).toContain('Showing 1–50 of 120')
    await w.find('[aria-label="Page 3"]').trigger('click')
    await flushPromises()
    expect(last().get('page')).toBe('3')
    // Header sort over the whole list: first click uses the column default, second reverses.
    const moduleHeader = w.findAll('th button').find((b) => b.text().startsWith('Module'))!
    await moduleHeader.trigger('click')
    await flushPromises()
    expect([last().get('sort'), last().get('order'), last().get('page')]).toEqual(['module', 'asc', '1'])
    await w.findAll('th button').find((b) => b.text().startsWith('Module'))!.trigger('click')
    await flushPromises()
    expect(last().get('order')).toBe('desc')
    // Non-sortable columns have no control.
    expect(w.findAll('th button').map((b) => b.text())).not.toContain('Outcome')
    // A filter change returns to page 1 and keeps the sort.
    await w.find('[aria-label="Page 2"]').trigger('click')
    await flushPromises()
    await w.find('[data-test="audit-module"] input').setValue('beta')
    await w.find('[data-test="audit-search"]').trigger('click')
    await flushPromises()
    expect([last().get('module'), last().get('page'), last().get('sort'), last().get('order')]).toEqual(['beta', '1', 'module', 'desc'])
  })

  it('keeps page, size and sort in the URL and adopts the page the server clamped to', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/ops/allowlist', component: Allowlist }] })
    await router.push('/ops/allowlist?allow.page=9&allow.size=10&allow.sort=created_at&allow.order=desc')
    await router.isReady()
    const calls = fetchMock((url) => {
      const q = new URL(url, 'https://x').searchParams
      return { items: [], total: 31, page: Math.min(Number(q.get('page')), 4), page_size: 10, sort: q.get('sort'), order: q.get('order') }
    })
    mount(Allowlist, { global: { plugins: [router] } })
    await flushPromises()
    const first = new URL(calls[0]!.url, 'https://x').searchParams
    expect([first.get('page'), first.get('page_size'), first.get('sort'), first.get('order')]).toEqual(['9', '10', 'created_at', 'desc'])
    expect(router.currentRoute.value.query['allow.page']).toBe('4') // server clamped 9 → 4
    // Invalid URL values fall back to defaults without an error.
    await router.push('/ops/allowlist?allow.sort=prefixes&allow.size=7')
    await flushPromises()
    const fb = new URL(calls.at(-1)!.url, 'https://x').searchParams
    expect([fb.get('sort'), fb.get('page_size')]).toEqual(['spiffe_id', '25'])
  })
})
