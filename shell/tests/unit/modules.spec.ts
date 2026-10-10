import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import Modules from '@/views/ops/Modules.vue'

type Call = { url: string; method: string; body?: unknown; csrf?: string | undefined }

const items = [
  { module: 'billing', display_name: 'Billing', identity: 'spiffe://example.org/svc/billing', state: 'down', registered: false, instances: 0, build_versions: [], last_version: '1.4.2', first_seen_at: '2026-10-01T08:00:00Z', last_seen_at: '2026-10-09T11:00:00Z', expected: true },
  { module: 'legacy', display_name: 'Legacy', identity: 'spiffe://example.org/svc/legacy', state: 'stopped', registered: false, instances: 0, build_versions: [], last_version: '0.9.0', first_seen_at: '2026-09-01T08:00:00Z', last_seen_at: '2026-09-02T08:00:00Z', expected: false },
  { module: 'sms-gw', display_name: 'SMS Gateway', identity: 'spiffe://example.org/svc/sms-gw', state: 'active', registered: true, instances: 1, build_versions: ['4.2.0'], last_version: '4.2.0', first_seen_at: '2026-10-09T10:06:16Z', last_seen_at: '2026-10-10T08:55:02Z', expected: true },
]

function backend(canManage: boolean): Call[] {
  const calls: Call[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET'
    calls.push({ url, method, body: init.body ? JSON.parse(String(init.body)) : undefined, csrf: (init.headers as Record<string, string> | undefined)?.['X-CSRF-Token'] })
    if (method === 'GET') return new Response(JSON.stringify({ can_manage: canManage, items }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    return new Response(null, { status: 204 })
  }))
  return calls
}

describe('modules (known modules catalogue)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  it('lists running, down and stopped modules with versions and last seen', async () => {
    backend(false)
    const w = mount(Modules, { attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="state-billing"]').text()).toContain('down')
    expect(w.find('[data-test="state-legacy"]').text()).toContain('stopped')
    expect(w.find('[data-test="state-sms-gw"]').text()).toContain('active')
    expect(w.find('[data-test="mod-billing"]').text()).toContain('1.4.2')
    expect(w.find('[data-test="mod-sms-gw"]').text()).toContain('SMS Gateway')
    expect(w.find('[data-test="down-count"]').text()).toContain('1')
    w.unmount()
  })

  it('an operator who is not an administrator sees no actions', async () => {
    backend(false)
    const w = mount(Modules, { attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="expected-billing"]').exists()).toBe(false)
    expect(w.find('[data-test="forget-billing"]').exists()).toBe(false)
    w.unmount()
  })

  it('an administrator switches expected with the CSRF header and the list reloads', async () => {
    const calls = backend(true)
    const w = mount(Modules, { attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="expected-billing"] input').setValue(false)
    await flushPromises()
    const patch = calls.find((c) => c.method === 'PATCH')!
    expect(patch.url).toBe('/gateway/v1/ops/catalogue/billing')
    expect(patch.body).toEqual({ expected: false })
    expect(patch.csrf).toBe('tok')
    expect(calls.filter((c) => c.method === 'GET' && c.url === '/gateway/v1/ops/catalogue').length).toBe(2)
    w.unmount()
  })

  it('forget asks first, is offered only for modules that are not registered, and deletes', async () => {
    const calls = backend(true)
    const w = mount(Modules, { attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="forget-sms-gw"]').exists()).toBe(false)
    await w.find('[data-test="forget-billing"]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    expect(document.body.textContent).toContain('Forget billing')
    ;(document.querySelector('[data-test="forget-confirm"]') as HTMLButtonElement).click()
    await flushPromises()
    const del = calls.find((c) => c.method === 'DELETE')!
    expect(del.url).toBe('/gateway/v1/ops/catalogue/billing')
    expect(del.csrf).toBe('tok')
    w.unmount()
  })
})

describe('modules: catalogue sources (phase 2)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  const withEntries = [
    { ...items[2]!, build_versions: ['4.2.0'], latest_version: '4.3.0', update_available: true, installable: true, summary: 'SMS API', repository: 'go-tangra/go-tangra-sms-gw' },
    { module: 'asterisk', display_name: 'Asterisk', state: 'available', registered: false, instances: 0, build_versions: [], expected: false, latest_version: '4.1.0', update_available: false, installable: true, summary: 'PBX observation' },
  ]
  function sourcesBackend(): Call[] {
    const calls: Call[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
      const method = init.method ?? 'GET'
      calls.push({ url, method, body: init.body ? JSON.parse(String(init.body)) : undefined, csrf: (init.headers as Record<string, string> | undefined)?.['X-CSRF-Token'] })
      const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'Content-Type': 'application/json' } })
      if (url === '/gateway/v1/ops/catalogue') return json({ can_manage: true, items: withEntries })
      if (url === '/gateway/v1/ops/catalogue/sources' && method === 'GET') return json({ sources: [{ repo: 'go-tangra/go-tangra-sms-gw', module: 'sms-gw', added_by: 'op1', added_at: '2026-10-10T08:00:00Z', last_checked_at: '2026-10-10T09:00:00Z' }, { repo: 'go-tangra/broken', added_by: 'op1', added_at: '2026-10-10T08:00:00Z', last_error: 'no catalogue entry in release v1.0.0' }], allowed_owners: ['go-tangra'] })
      if (url === '/gateway/v1/ops/catalogue/sources' && method === 'POST') return json({ repo: 'go-tangra/go-tangra-asterisk', module: 'asterisk', version: '4.1.0', outcome: 'stored' }, 201)
      return new Response(null, { status: 204 })
    }))
    return calls
  }

  it('shows available modules, latest versions and update notices', async () => {
    sourcesBackend()
    const w = mount(Modules, { attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="state-asterisk"]').text()).toContain('available')
    expect(w.find('[data-test="update-sms-gw"]').text()).toContain('4.3.0')
    expect(w.find('[data-test="update-asterisk"]').exists()).toBe(false)
    expect(w.find('[data-test="mod-asterisk"]').text()).toContain('4.1.0')
    w.unmount()
  })

  it('administrators see sources with their errors, add one and refresh one', async () => {
    const calls = sourcesBackend()
    const w = mount(Modules, { attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="source-go-tangra/broken"]').text()).toContain('no catalogue entry')
    await w.find('[data-test="source-add"] input').setValue('go-tangra/go-tangra-asterisk')
    await w.find('[data-test="source-add-button"]').trigger('click')
    await flushPromises()
    const add = calls.find((c) => c.method === 'POST' && c.url === '/gateway/v1/ops/catalogue/sources')!
    expect(add.body).toEqual({ repo: 'go-tangra/go-tangra-asterisk' })
    expect(add.csrf).toBe('tok')
    expect(w.text()).toContain('asterisk 4.1.0: stored')
    await w.find('[data-test="source-refresh-go-tangra/go-tangra-sms-gw"]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.method === 'POST' && c.url === '/gateway/v1/ops/catalogue/sources/go-tangra/go-tangra-sms-gw/refresh')).toBe(true)
    w.unmount()
  })
})
