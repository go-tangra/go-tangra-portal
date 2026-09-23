import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { defineComponent, h, nextTick } from 'vue'

const { init, registerRemotes, loadRemote } = vi.hoisted(() => ({ init: vi.fn<(opts: unknown) => object>(() => ({})), registerRemotes: vi.fn(), loadRemote: vi.fn() }))
vi.mock('@module-federation/enhanced/runtime', () => ({ init, registerRemotes, loadRemote }))

import { shared, hostConfig } from '../../module-federation.config'
import { federationHost, resetFederation } from '@/federation/runtime'
import { composeModules, failedModules } from '@/federation/boot'
import { useSession } from '@/stores/session'
import { createMemoryHistory, createRouter } from 'vue-router'
import ModuleBoundary from '@/components/ModuleBoundary.vue'

// T066: the host shares exactly the kit-era singletons (specs/003 contracts/federation.md,
// amended by specs/013). Vuetify is gone: a remote that still requests it fails
// into its own boundary and never reaches the shared scope.
describe('shared runtime (US5)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    resetFederation()
    failedModules.clear()
    init.mockClear()
    loadRemote.mockReset()
  })

  it('shares exactly vue, vue-router, pinia, @casl/ability, @casl/vue, zod and the @freya/ui entry points', () => {
    expect(Object.keys(shared).sort()).toEqual(['@casl/ability', '@casl/vue', '@freya/ui', '@freya/ui/api', '@freya/ui/forms', 'pinia', 'vue', 'vue-router', 'zod'].sort())
    expect(shared).not.toHaveProperty('vuetify')
    for (const [name, cfg] of Object.entries(shared)) {
      expect(cfg.singleton, name).toBe(true)
      expect(cfg.requiredVersion, name).toMatch(/^\^\d+\.\d+\.\d+$/)
    }
    for (const name of ['zod', '@freya/ui', '@freya/ui/forms', '@freya/ui/api']) expect((shared as Record<string, { strictVersion?: boolean }>)[name]?.strictVersion, name).toBe(true)
    federationHost()
    const opts = init.mock.calls[0]?.[0] as { name: string; shared: Record<string, unknown> } | undefined
    expect(opts?.name).toBe(hostConfig.name)
    expect(Object.keys(opts?.shared ?? {})).not.toContain('vuetify')
  })

  it('a remote that requests vuetify fails to load, is marked failed and its siblings compose; a render-time miss hits the boundary', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    loadRemote.mockImplementation(async (id: string) => {
      if (id === 'legacy/routes') throw new Error('Shared module vuetify is not registered in the host')
      return { default: [{ path: '/good', component: { template: '<p>good</p>' } }] }
    })
    const s = useSession()
    s.apply({ user_id: 'u', tenant_id: 't' })
    s.modules = [
      { module: 'legacy', remote: { entry: '/m/legacy/mf-manifest.json' } },
      { module: 'good', remote: { entry: '/m/good/mf-manifest.json' } },
    ]
    const router = createRouter({ history: createMemoryHistory(), routes: [] })
    await composeModules(router)
    expect(failedModules.has('legacy')).toBe(true)
    expect(router.hasRoute('remote:good:0')).toBe(true)
    expect(router.getRoutes().some((r) => String(r.name).startsWith('remote:legacy'))).toBe(false)
    // A remote that resolves vuetify lazily (at render) throws inside its own boundary.
    const Lazy = defineComponent({ setup() { throw new Error('Shared module vuetify is not registered in the host') } })
    const w = mount(ModuleBoundary, { props: { module: 'legacy' }, slots: { default: () => h(Lazy) }, global: { config: { errorHandler: () => undefined } } })
    await nextTick()
    expect(w.find('[data-test="module-error"]').exists()).toBe(true)
    expect(w.find('[data-test="module-error"] button').text()).toContain('Retry')
  })
})
