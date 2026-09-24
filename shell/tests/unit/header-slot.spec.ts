/* eslint-disable vue/one-component-per-file, vue/require-default-prop -- test doubles */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { defineComponent, h, nextTick } from 'vue'

const { loadRemote } = vi.hoisted(() => ({ loadRemote: vi.fn() }))
vi.mock('@module-federation/enhanced/runtime', () => ({ init: vi.fn(() => ({})), registerRemotes: vi.fn(), loadRemote }))

import { headerSlots, mountModule, unmountModule } from '@/federation/boot'
import Default from '@/layouts/Default.vue'
import { useSession } from '@/stores/session'

function mountLayout() {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: { template: '<p>home</p>' } }] })
  const w = mount(Default, { global: { plugins: [router], stubs: { RouterView: true }, config: { errorHandler: () => undefined } } })
  return { router, w }
}

describe('module header slot (./header)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    loadRemote.mockReset()
    headerSlots.clear()
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1', display_name: 'Ana' })
  })

  it('renders a module header component in the app bar with the boot context and removes it on unmount', async () => {
    const seen: unknown[] = []
    const Bell = defineComponent({
      props: { ability: Object, session: Object, api: Object },
      setup(props) {
        seen.push(props)
        return () => h('button', { 'data-test': 'bell' }, 'bell')
      },
    })
    loadRemote.mockImplementation(async (id: string) => {
      if (id === 'notification/routes') return { routes: [] }
      if (id === 'notification/header') return { default: Bell }
      throw new Error('unknown ' + id)
    })
    const { router, w } = mountLayout()
    await mountModule(router, 'notification')
    await flushPromises()
    expect(headerSlots.has('notification')).toBe(true)
    expect(w.find('[data-test="header-notification"]').exists()).toBe(true)
    expect(w.find('[data-test="header-notification"]').text()).toBe('bell') // the slot attribute lands on the component root
    expect((seen[0] as { session: { userId: string } }).session.userId).toBe('u1')
    expect((seen[0] as { api: unknown }).api).toBeTruthy()
    // Bar order: theme toggle, then module slots, then the avatar.
    const bar = w.find('header')
    const html = bar.html()
    expect(html.indexOf('theme-toggle')).toBeLessThan(html.indexOf('header-notification'))
    expect(html.indexOf('header-notification')).toBeLessThan(html.indexOf('me-avatar'))
    unmountModule(router, 'notification')
    await flushPromises()
    expect(w.find('[data-test="header-notification"]').exists()).toBe(false)
  })

  it('renders nothing for a module without ./header', async () => {
    loadRemote.mockImplementation(async (id: string) => {
      if (id === 'plain/routes') return { routes: [] }
      throw new Error('unknown ' + id)
    })
    const { router, w } = mountLayout()
    await mountModule(router, 'plain')
    await flushPromises()
    expect(headerSlots.size).toBe(0)
    expect(w.find('[data-test^="header-"]').exists()).toBe(false)
  })

  it('isolates a throwing header component: the bar stays intact and shows no error card', async () => {
    const Boom = defineComponent({ setup() { throw new Error('header failed') } })
    loadRemote.mockImplementation(async (id: string) => {
      if (id === 'broken/routes') return { routes: [] }
      if (id === 'broken/header') return { default: Boom }
      throw new Error('unknown ' + id)
    })
    const { router, w } = mountLayout()
    await mountModule(router, 'broken')
    await flushPromises()
    await nextTick()
    expect(w.find('[data-test="module-error"]').exists()).toBe(false)
    expect(w.find('[data-test="header-silent-broken"]').exists()).toBe(true)
    expect(w.find('[data-test="theme-toggle"]').exists()).toBe(true)
    expect(w.find('[data-test="me-avatar"]').exists()).toBe(true)
  })
})
