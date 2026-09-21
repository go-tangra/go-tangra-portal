import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import Default from '@/layouts/Default.vue'
import { router } from '@/router'
import { SESSION_CHANGED_EVENT, useSession } from '@/stores/session'
import { boot } from '@/federation/boot'

describe('shell header', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('shows the avatar and display name, or initials without a picture', async () => {
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1', display_name: 'Dana Kovač', avatar_url: '/api/v1/users/u1/avatar/abc' })
    // The layout needs Vuetify's application frame (v-app) as an ancestor.
    const Host = defineComponent({ render: () => h(VApp, () => h(Default)) })
    const w = mount(Host, { global: { plugins: [createVuetify({ components, directives }), router], stubs: { RouterView: true } } })
    await flushPromises()
    expect(w.find('[data-test="me-name"]').text()).toBe('Dana Kovač')
    expect(w.find('[data-test="me-avatar"] img, [data-test="me-avatar"] .v-img').exists()).toBe(true)
    s.apply({ user_id: 'u1', tenant_id: 't1', display_name: 'Dana Kovač', avatar_url: '' })
    await flushPromises()
    expect(w.find('[data-test="me-avatar"]').text()).toBe('DK')
    w.unmount()
  })

  it('refetches the identity when a module reports a profile change', async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url === '/gateway/v1/me') return new Response(JSON.stringify({ user_id: 'u1', tenant_id: 't1', roles: [], display_name: 'Before' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      return new Response(JSON.stringify([]), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    vi.stubGlobal('fetch', fetch)
    vi.stubGlobal('EventSource', class { onmessage = null; onerror = null; onopen = null; addEventListener() {} close() {} })
    const stop = await boot(router)
    const s = useSession()
    expect(s.displayName).toBe('Before')
    fetch.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url === '/gateway/v1/me') return new Response(JSON.stringify({ user_id: 'u1', tenant_id: 't1', roles: [], display_name: 'After' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      return new Response(JSON.stringify([]), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    window.dispatchEvent(new CustomEvent(SESSION_CHANGED_EVENT))
    await flushPromises()
    expect(s.displayName).toBe('After')
    stop()
  })
})
