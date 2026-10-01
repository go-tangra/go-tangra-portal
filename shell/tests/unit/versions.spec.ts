import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import Home from '@/views/Home.vue'
import Registrations from '@/views/ops/Registrations.vue'
import { useSession } from '@/stores/session'
import { releaseLabel } from '@/api/versions'
import type { components } from '@/api/schema'

type Module = components['schemas']['Module']

describe('releaseLabel', () => {
  it('shows the build version, never the manifest contract version', () => {
    expect(releaseLabel({ build_version: '4.10.2', build_versions: ['4.10.2'] })).toBe('4.10.2')
    expect(releaseLabel({ version: '1.0.0', build_version: '', build_versions: [] } as Module)).toBe('')
    expect(releaseLabel({ version: '1.0.0' } as Module)).toBe('')
  })

  it('shows every release during a rollout', () => {
    expect(releaseLabel({ build_version: '4.10.2', build_versions: ['4.10.1', '4.10.2'] })).toBe('4.10.1 → 4.10.2')
  })

  it('falls back to build_version when the list is absent', () => {
    expect(releaseLabel({ build_version: '4.6.2', build_versions: null })).toBe('4.6.2')
  })
})

describe('landing page', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists each module with the release its instances run', async () => {
    const s = useSession()
    s.modules = [
      { module: 'ipam', display_name: 'IPAM', version: '1.0.0', build_version: '4.10.2', build_versions: ['4.10.2'], state: 'active' },
      { module: 'auth', display_name: 'Auth', version: '1.2.0', build_version: '', build_versions: [], state: 'active' },
    ]
    const w = mount(Home)
    await flushPromises()
    expect(w.find('[data-test="version-ipam"]').text()).toBe('4.10.2')
    expect(w.find('[data-test="version-auth"]').text()).toBe('')
    expect(w.text()).not.toContain('1.0.0')
    expect(w.text()).not.toContain('1.2.0')
  })
})

describe('registrations view', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('shows the release next to the module and the manifest version apart', async () => {
    const item = { module: 'ipam', identity: 'spiffe://example.org/svc/ipam', state: 'active', instances: 1, unhealthy: 0, manifest: { version: '1.0.0', display_name: 'IPAM' }, build_versions: ['4.10.2'], traffic: { requests_1m: 0, refusals_1m: 0, p95_ms: 0 } }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ items: [item], total: 1, page: 1, page_size: 25, sort: 'module', order: 'asc' }), { status: 200 })))
    const w = mount(Registrations)
    await flushPromises()
    const row = w.find('[data-test="reg-ipam"]').text()
    expect(row).toContain('IPAM 4.10.2')
    expect(row).toContain('1.0.0')
  })
})
