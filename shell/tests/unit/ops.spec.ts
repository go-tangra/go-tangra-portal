import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
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
      return [reg('alpha', state)]
    })
    const w = mount(Registrations, { global: { plugins: [createVuetify()] } })
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
    const calls = fetchMock((url) => (url.endsWith('/revoke') ? 204 : [reg('alpha', 'active')]))
    const w = mount(Registrations, { global: { plugins: [createVuetify()], stubs: { VDialog: { template: '<div><slot /></div>' } } }, attachTo: document.body })
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
      return entries
    })
    const w = mount(Allowlist, { global: { plugins: [createVuetify()] } })
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

  it('renders the audit trail with filters and paging', async () => {
    const calls = fetchMock(() => ({ events: [{ ts: 't1', event_type: 'module_drained', module: 'alpha', actor_kind: 'operator', actor_id: 'op', subject_kind: 'module', subject_id: 'alpha', outcome: 'ok', reason: 'drained', correlation_id: '', details: {} }], next_cursor: 't1' }))
    const w = mount(Audit, { global: { plugins: [createVuetify()] } })
    await flushPromises()
    expect(w.find('[data-test="audit-module_drained"]').exists()).toBe(true)
    await w.find('[data-test="audit-more"]').trigger('click')
    await flushPromises()
    expect(calls[1]!.url).toContain('cursor=t1')
    expect(w.findAll('[data-test="audit-module_drained"]').length).toBe(2)
  })
})
