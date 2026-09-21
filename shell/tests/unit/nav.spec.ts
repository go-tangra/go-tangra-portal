import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import { createRouter, createMemoryHistory } from 'vue-router'
import { defineComponent, h } from 'vue'
import { VApp } from 'vuetify/components'
import Default from '@/layouts/Default.vue'
import { useSession } from '@/stores/session'

describe('navigation from manifests', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists permitted entries ordered across modules and the operations entry for operators', async () => {
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1', operator: true })
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
      { module: 'hello', display_name: 'Hello', nav: [{ title: 'Hello', path: '/hello', order: 90 }] },
      { module: 'auth', display_name: 'Authentication', nav: [{ title: 'Users', path: '/console/admin/users', order: 800 }, { title: 'Security', path: '/console/security', order: 900 }] },
      { module: 'warden', display_name: 'Warden', nav: [{ title: 'Secrets', path: '/warden', icon: 'mdi-key-variant', order: 100 }, { title: 'Folders', path: '/warden/folders', order: 110 }] },
    ]), { status: 200 })))
    await s.loadModules()
    // One menu per module, ordered by its first entry, entries as sub-items.
    expect(s.navGroups.map((g) => [g.module, g.title, g.icon, g.entries.map((e) => e.title)])).toEqual([
      ['hello', 'Hello', 'mdi-view-module-outline', ['Hello']],
      ['warden', 'Warden', 'mdi-key-variant', ['Secrets', 'Folders']],
      ['auth', 'Authentication', 'mdi-view-module-outline', ['Users', 'Security']],
    ])
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:pathMatch(.*)*', component: { template: '<div />' } }] })
    await router.push('/warden/folders')
    await router.isReady()
    // Layout components need the v-app layout context.
    const Host = defineComponent({ setup: () => () => h(VApp, () => h(Default, null, { default: () => h('p', 'content') })) })
    const w = mount(Host, { global: { plugins: [createVuetify(), router] } })
    await flushPromises()
    const groups = w.findAll('[data-test^="nav-group-"]').map((n) => n.attributes('data-test'))
    expect(groups).toEqual(['nav-group-hello', 'nav-group-warden', 'nav-group-auth'])
    // The menu of the module owning the current route is open; the others are collapsed
    // (Vuetify marks a collapsed menu's items inert; jsdom's computed display is unreliable after toggles).
    const visible = (sel: string) => w.findAll(sel).filter((n) => n.element.closest('.v-list-group__items')?.getAttribute('inert') !== 'true').length
    expect(visible('[data-test="nav-warden"]')).toBe(2)
    expect(visible('[data-test="nav-auth"]')).toBe(0)
    await w.find('[data-test="nav-group-auth"]').trigger('click')
    await flushPromises()
    expect(visible('[data-test="nav-auth"]')).toBe(2)
    expect(w.text()).toContain('Gateway operations')
    s.operator = false
    await w.vm.$nextTick()
    await w.vm.$nextTick()
    expect(w.find('[data-test="nav-ops"]').exists()).toBe(false)
  })
})
