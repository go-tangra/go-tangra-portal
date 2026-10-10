import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import { UiSelect } from '@go-tangra/ui'
import JoinWizard from '@/components/ops/JoinWizard.vue'
import type { components } from '@/api/schema'

// Spec 037: the add-module wizard delivers the bundle through a host's
// enrolled inventory agent.
type Call = { url: string; method: string; body?: unknown; csrf?: string | undefined }

const sms: components['schemas']['CatalogueItem'] = { module: 'sms-gw', display_name: 'SMS Gateway', state: 'available', registered: false, instances: 0, build_versions: [], expected: false,
  latest_version: '4.3.0', update_available: false, installable: true,
  host_inputs: [{ key: 'MODULE_ADVERTISE_HOST', label: 'Host name', pattern: '^[a-z0-9.-]+$' }, { key: 'MODULE_BIND_IP', label: 'Bind IP', pattern: '^[0-9.]+$' },
    { key: 'SMS_PUBLIC_PORT', label: 'Port', pattern: '^[0-9]+$', default: '9901' }] }

const hosts = [
  { host_id: 'h1', hostname: 'pbx1.example.org', os_name: 'Ubuntu', agent_online: true, capability: 'enabled', ip_addresses: ['10.0.0.5', '192.168.1.5'] },
  { host_id: 'h2', hostname: 'win1', os_name: 'Windows', agent_online: true, capability: 'not_supported_platform', ip_addresses: [] },
]

function backend(opts: { deliverStatus?: number; deliverBody?: unknown; targetsStatus?: number } = {}): Call[] {
  const calls: Call[] = []
  let polls = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET'
    calls.push({ url, method, body: init.body ? JSON.parse(String(init.body)) : undefined, csrf: (init.headers as Record<string, string> | undefined)?.['X-CSRF-Token'] })
    const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'Content-Type': 'application/json' } })
    if (url.startsWith('/gateway/v1/ops/catalogue/sms-gw/targets')) {
      return opts.targetsStatus ? json({ reason: 'temporarily_unavailable' }, opts.targetsStatus) : json({ hosts, truncated: false })
    }
    if (url === '/gateway/v1/ops/catalogue/sms-gw/deliver') {
      if (opts.deliverStatus) return json(opts.deliverBody, opts.deliverStatus)
      return json({ join_id: 'j1', expires_at: '2026-10-11T08:00:00Z', delivery: { host_id: 'h1', hostname: 'pbx1.example.org', state: 'pending', agent_online: true } }, 202)
    }
    if (url === '/gateway/v1/ops/catalogue/sms-gw/join/j1') {
      polls++
      return json({ id: 'j1', module: 'sms-gw', version: '4.3.0', created_at: '2026-10-10T08:00:00Z', expires_at: '2026-10-11T08:00:00Z', channel: 'agent',
        token_used: polls > 1, registered: polls > 2, state: polls > 2 ? 'active' : undefined,
        delivery: { host_id: 'h1', hostname: 'pbx1.example.org', state: polls > 0 ? 'installed' : 'pending', agent_online: true } })
    }
    return new Response(null, { status: 204 })
  }))
  return calls
}

async function chooseAgent(w: ReturnType<typeof mount>): Promise<void> {
  w.findAllComponents(UiSelect)[0]!.vm.$emit('update:modelValue', 'agent')
  await flushPromises()
  ;(document.querySelector('[data-test="join-host-search"]') as HTMLButtonElement).click()
  await flushPromises()
}

function input(key: string): HTMLInputElement {
  return document.querySelector(`[data-test="input-${key}"] input`) as HTMLInputElement
}

describe('add-module wizard: deliver through the inventory agent', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  it('is not offered without agent delivery', async () => {
    backend()
    const w = mount(JoinWizard, { props: { item: sms, canDeliver: false }, attachTo: document.body })
    await flushPromises()
    expect(document.querySelector('[data-test="join-channel"]')).toBeNull()
    expect(document.querySelector('[data-test="join-download"]')).not.toBeNull()
    w.unmount()
  })

  it('lists eligible hosts, pre-fills host inputs, delivers with CSRF and follows the delivery', async () => {
    const calls = backend()
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const w = mount(JoinWizard, { props: { item: sms, canDeliver: true }, attachTo: document.body })
    await flushPromises()
    await chooseAgent(w)
    expect(document.querySelector('[data-test="join-ineligible"]')?.textContent).toContain('win1: not supported on this platform')
    expect(input('MODULE_ADVERTISE_HOST').value).toBe('pbx1.example.org')
    expect(input('MODULE_BIND_IP').value).toBe('10.0.0.5')
    expect(input('SMS_PUBLIC_PORT').value).toBe('9901')
    ;(document.querySelector('[data-test="join-deliver"]') as HTMLButtonElement).click()
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('/gateway/v1/ops/catalogue/sms-gw/deliver')
    expect(post.body).toEqual({ host_id: 'h1', inputs: { MODULE_ADVERTISE_HOST: 'pbx1.example.org', MODULE_BIND_IP: '10.0.0.5', SMS_PUBLIC_PORT: '9901' }, ttl_hours: 24 })
    expect(post.csrf).toBe('tok')
    expect(document.querySelector('[data-test="step-delivery"]')?.textContent).toContain('queued for the agent')
    await vi.advanceTimersByTimeAsync(5000)
    await flushPromises()
    expect(document.querySelector('[data-test="step-delivery"]')?.textContent).toContain('written on the host')
    expect(document.querySelector('[data-test="join-start-hint"]')).not.toBeNull()
    for (let i = 0; i < 2; i++) {
      await vi.advanceTimersByTimeAsync(5000)
      await flushPromises()
    }
    expect(document.querySelector('[data-test="step-registered"]')?.textContent).toContain('done')
    expect(w.emitted('installed')).toBeTruthy()
    vi.useRealTimers()
    w.unmount()
  })

  it('an ineligible host is explained', async () => {
    backend({ deliverStatus: 409, deliverBody: { reason: 'conflict', detail: { reason: 'upgrade_required' } } })
    const w = mount(JoinWizard, { props: { item: sms, canDeliver: true }, attachTo: document.body })
    await flushPromises()
    await chooseAgent(w)
    ;(document.querySelector('[data-test="join-deliver"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(document.querySelector('[data-test="join-error"]')?.textContent).toContain('the agent is too old')
    w.unmount()
  })

  it('an unreachable inventory is not an outage', async () => {
    backend({ targetsStatus: 503 })
    const w = mount(JoinWizard, { props: { item: sms, canDeliver: true }, attachTo: document.body })
    await flushPromises()
    await chooseAgent(w)
    expect(document.querySelector('[data-test="join-error"]')?.textContent).toContain('not reachable')
    expect((document.querySelector('[data-test="join-deliver"]') as HTMLButtonElement).disabled).toBe(true)
    w.unmount()
  })
})
