import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { defineComponent, h, nextTick } from 'vue'

const { loadRemote } = vi.hoisted(() => ({ loadRemote: vi.fn() }))
vi.mock('@module-federation/enhanced/runtime', () => ({ init: vi.fn(() => ({})), registerRemotes: vi.fn(), loadRemote }))

import { composeModules, failedModules, mountModule, unmountModule, wrapRoute } from '@/federation/boot'
import ModuleBoundary from '@/components/ModuleBoundary.vue'
import { useSession } from '@/stores/session'

describe('module composition', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    loadRemote.mockReset()
    failedModules.clear()
  })

  it('mounts remote routes under an error boundary and calls ./boot', async () => {
    const booted: unknown[] = []
    loadRemote.mockImplementation(async (id: string) => {
      if (id === 'hello/routes') return { routes: [{ path: '/hello', component: { template: '<p>hi</p>' } }] }
      if (id === 'hello/boot') return { default: (ctx: unknown) => booted.push(ctx) }
      throw new Error('unknown ' + id)
    })
    const router = createRouter({ history: createMemoryHistory(), routes: [] })
    await mountModule(router, 'hello')
    expect(router.hasRoute('remote:hello:0')).toBe(true)
    expect(booted).toHaveLength(1)
    expect((booted[0] as { ability: unknown }).ability).toBeTruthy()
    unmountModule(router, 'hello')
    expect(router.hasRoute('remote:hello:0')).toBe(false)
  })

  it('isolates a failing remote and composes the rest', async () => {
    loadRemote.mockImplementation(async (id: string) => {
      if (id === 'good/routes') return { default: [{ path: '/good', component: { template: '<p>good</p>' } }] }
      throw new Error('down')
    })
    const s = useSession()
    s.apply({ user_id: 'u', tenant_id: 't' })
    s.modules = [
      { module: 'good', remote: { entry: '/m/good/mf-manifest.json' } },
      { module: 'broken', remote: { entry: '/m/broken/mf-manifest.json' } },
    ]
    const router = createRouter({ history: createMemoryHistory(), routes: [] })
    await composeModules(router)
    expect(router.hasRoute('remote:good:0')).toBe(true)
    expect(failedModules.has('broken')).toBe(true)
    expect(failedModules.has('good')).toBe(false)
    // A withdrawn module is unmounted on the next composition.
    s.modules = [{ module: 'broken', remote: { entry: '/m/broken/mf-manifest.json' } }]
    await composeModules(router)
    expect(router.hasRoute('remote:good:0')).toBe(false)
  })

  it('renders the error card only for the failing module with a retry', async () => {
    const Boom = defineComponent({ setup() { throw new Error('render failed') } })
    const w = mount(ModuleBoundary, { props: { module: 'orders' }, slots: { default: () => h(Boom) }, global: { config: { errorHandler: () => undefined } } })
    await nextTick()
    await nextTick()
    expect(w.find('[data-test="module-error"]').exists()).toBe(true)
    expect(w.text()).toContain('orders module could not be loaded')
    await w.find('[data-test="module-error"] button').trigger('click')
    await nextTick()
    expect(w.find('[data-test="module-error"]').exists()).toBe(true) // the remote throws again on retry
    const wrapped = wrapRoute({ path: '/x', component: { template: '<p>x</p>' }, children: [{ path: 'y', component: { template: '<p>y</p>' } }] }, 'orders')
    expect(wrapped.meta?.module).toBe('orders')
    expect(wrapped.children?.[0]?.meta?.module).toBe('orders')
  })
})
