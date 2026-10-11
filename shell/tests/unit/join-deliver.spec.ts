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
  { host_id: 'h1', hostname: 'pbx1.example.org', os_name: 'Ubuntu', agent_online: true, capability: 'enabled', ip_addresses: ['203.0.113.7', '2001:db8::7', 'fd00::5', '10.0.0.5'] },
  { host_id: 'h2', hostname: 'win1', os_name: 'Windows', agent_online: true, capability: 'not_supported_platform', ip_addresses: [] },
]

function backend(opts: { deliverStatus?: number; deliverBody?: unknown; targetsStatus?: number; failWith?: string } = {}): Call[] {
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
      if (opts.failWith) {
        return json({ id: 'j1', module: 'sms-gw', version: '4.3.0', created_at: '2026-10-10T08:00:00Z', expires_at: '2026-10-11T08:00:00Z', channel: 'agent',
          token_used: false, registered: false, delivery: { host_id: 'h1', hostname: 'pbx1.example.org', state: 'failed', reason: opts.failWith, agent_online: true } })
      }
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

  it('offers the host\'s addresses for *_IP inputs, private first, and keeps the input editable', async () => {
    const calls = backend()
    const w = mount(JoinWizard, { props: { item: sms, canDeliver: true }, attachTo: document.body })
    await flushPromises()
    await chooseAgent(w)
    const picker = w.findAllComponents(UiSelect).find((c) => c.attributes('data-test') === 'pick-MODULE_BIND_IP')!
    expect((picker.props('options') as { value: string }[]).map((o) => o.value)).toEqual(['10.0.0.5', 'fd00::5', '203.0.113.7', '2001:db8::7'])
    expect((picker.props('options') as { title: string }[])[2]!.title).toBe('203.0.113.7 (public)')
    expect(document.querySelector('[data-test="pick-MODULE_ADVERTISE_HOST"]')).toBeNull()
    picker.vm.$emit('update:modelValue', '203.0.113.7')
    await flushPromises()
    expect(input('MODULE_BIND_IP').value).toBe('203.0.113.7')
    const el = input('MODULE_BIND_IP')
    el.value = '172.16.0.9'
    el.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('[data-test="join-deliver"]') as HTMLButtonElement).click()
    await flushPromises()
    expect((calls.find((c) => c.method === 'POST')!.body as { inputs: Record<string, string> }).inputs.MODULE_BIND_IP).toBe('172.16.0.9')
    w.unmount()
  })

  it('a failed delivery is explained, stops polling and can be delivered again', async () => {
    const calls = backend({ failWith: 'fetch_budget' })
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const w = mount(JoinWizard, { props: { item: sms, canDeliver: true }, attachTo: document.body })
    await flushPromises()
    await chooseAgent(w)
    ;(document.querySelector('[data-test="join-deliver"]') as HTMLButtonElement).click()
    await flushPromises()
    await vi.advanceTimersByTimeAsync(5000)
    await flushPromises()
    const alert = document.querySelector('[data-test="join-delivery-failed"]')?.textContent ?? ''
    expect(alert).toContain('failed')
    expect(alert).toContain("the host's agent could not get the bundle")
    expect(alert).not.toContain('fetch_budget')
    expect(document.querySelector('[data-test="step-token"]')).toBeNull()
    const polls = calls.filter((c) => c.url.endsWith('/join/j1')).length
    await vi.advanceTimersByTimeAsync(20000)
    await flushPromises()
    expect(calls.filter((c) => c.url.endsWith('/join/j1')).length).toBe(polls)
    ;(document.querySelector('[data-test="join-again"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(document.querySelector('[data-test="join-deliver"]')).not.toBeNull()
    expect(input('MODULE_ADVERTISE_HOST').value).toBe('pbx1.example.org')
    expect(w.emitted('installed')).toBeFalsy()
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

  it('marks optional inputs and hides secrets', async () => {
    backend()
    const pbx = { ...sms, host_inputs: [...(sms.host_inputs ?? []),
      { key: 'ASTERISK_AMI_ADDRESS', label: 'AMI address', pattern: '^[a-z0-9.]+:[0-9]+$', optional: true },
      { key: 'ASTERISK_AMI_SECRET', label: 'AMI secret', pattern: '^[^ ]+$', optional: true }] }
    const w = mount(JoinWizard, { props: { item: pbx, canDeliver: false }, attachTo: document.body })
    await flushPromises()
    const label = (key: string) => document.querySelector(`[data-test="input-${key}"]`)?.textContent ?? ''
    expect(label('ASTERISK_AMI_ADDRESS')).toContain('AMI address (optional)')
    expect(label('MODULE_ADVERTISE_HOST')).not.toContain('(optional)')
    expect(input('ASTERISK_AMI_SECRET').type).toBe('password')
    expect(input('ASTERISK_AMI_ADDRESS').type).toBe('text')
    w.unmount()
  })
})
