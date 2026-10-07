import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import Enrollment from '@/views/ops/Enrollment.vue'
import { enrollmentSchema } from '@/schemas/ops'

type Call = { url: string; init: RequestInit }
function fetchMock(status: number, body: unknown): Call[] {
  const calls: Call[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init })
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  }))
  return calls
}
const minted = { token: 'eyJ.enrol.token', expires_at: '2026-10-07T12:30:00Z', spiffe_ids: ['spiffe://example.org/svc/sms-gw'], tenant_id: '00000000-0000-0000-0000-000000000001' }

describe('enrolment tokens', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.cookie = '__Host-csrf=tok; Secure; Path=/'
  })

  it('the form takes service names or SPIFFE ids, 5-30 minutes and an optional tenant UUID', () => {
    expect(enrollmentSchema.parse({ services: ' sms-gw , spiffe://example.org/svc/lcm ', ttl: '30', tenant_id: '' })).toEqual({ services: ['sms-gw', 'spiffe://example.org/svc/lcm'], ttl: '30', tenant_id: '' })
    expect(enrollmentSchema.safeParse({ services: '', ttl: '30', tenant_id: '' }).success).toBe(false)
    expect(enrollmentSchema.safeParse({ services: 'Bad_Name', ttl: '30', tenant_id: '' }).success).toBe(false)
    expect(enrollmentSchema.safeParse({ services: 'sms-gw', ttl: '60', tenant_id: '' }).success).toBe(false)
    expect(enrollmentSchema.safeParse({ services: 'sms-gw', ttl: '10', tenant_id: 'nope' }).success).toBe(false)
  })

  it('mints with the CSRF header, shows the token once with a copy button, and starts over', async () => {
    const calls = fetchMock(201, minted)
    const written: string[] = []
    Object.assign(navigator, { clipboard: { writeText: vi.fn(async (v: string) => void written.push(v)) } })
    const w = mount(Enrollment, { attachTo: document.body })
    const input = w.find('[data-test="enroll-services"] input')
    await input.setValue('sms-gw')
    await w.find('[data-test="enroll-form"]').trigger('submit')
    await flushPromises()
    expect(calls.length).toBe(1)
    expect(calls[0]!.url).toBe('/gateway/v1/ops/enrollment-tokens')
    expect((calls[0]!.init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok')
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ services: ['sms-gw'], ttl_seconds: 1800 })
    expect((w.find('[data-test="enroll-token"] textarea').element as HTMLTextAreaElement).value).toBe('eyJ.enrol.token')
    expect(w.find('[data-test="enroll-details"]').text()).toContain('spiffe://example.org/svc/sms-gw')
    expect(w.find('[data-test="enroll-form"]').exists()).toBe(false)
    await w.find('[data-test="enroll-copy"]').trigger('click')
    await flushPromises()
    expect(written).toEqual(['eyJ.enrol.token'])
    await w.find('[data-test="enroll-another"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="enroll-token"]').exists()).toBe(false)
    expect(w.find('[data-test="enroll-form"]').exists()).toBe(true)
    // Nothing is kept in the browser.
    expect(localStorage.getItem('freya.enrollment')).toBeNull()
    w.unmount()
  })

  it('a refusal stays in the form and shows no token', async () => {
    fetchMock(403, { reason: 'forbidden' })
    const w = mount(Enrollment, { attachTo: document.body })
    await w.find('[data-test="enroll-services"] input').setValue('sms-gw')
    await w.find('[data-test="enroll-form"]').trigger('submit')
    await flushPromises()
    expect(w.find('[data-test="enroll-token"]').exists()).toBe(false)
    expect(w.find('[data-test="enroll-form"]').text()).toMatch(/not allowed|forbidden/i)
    w.unmount()
  })
})
