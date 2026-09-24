import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Default from '@/layouts/Default.vue'
import { router } from '@/router'
import { SESSION_CHANGED_EVENT, useSession } from '@/stores/session'
import { boot } from '@/federation/boot'

describe('shell header', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('shows the avatar and display name, or initials without a picture', async () => {
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1', display_name: 'Dana Kovač', avatar_url: '/api/v1/users/u1/avatar/abc' })
    const w = mount(Default, { global: { plugins: [router], stubs: { RouterView: true } } })
    await flushPromises()
    expect(w.find('[data-test="me-name"]').text()).toBe('Dana Kovač')
    expect(w.find('[data-test="me-avatar"] img').exists()).toBe(true)
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

describe('shell frame on the kit (UiAppShell)', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('collapses the drawer below lg, renders manifest icons as kit icons and toggles the theme', async () => {
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1', display_name: 'Dana', operator: true })
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
      { module: 'warden', display_name: 'Warden', nav: [{ title: 'Secrets', path: '/warden', icon: 'mdi-key-variant', order: 100 }] },
    ]), { status: 200 })))
    await s.loadModules()
    localStorage.clear()
    document.documentElement.setAttribute('data-theme', 'freya-light')
    ;(globalThis as unknown as { __vw: number }).__vw = 360
    const w = mount(Default, { global: { plugins: [router], stubs: { RouterView: true } }, attachTo: document.body })
    await flushPromises()
    const nav = w.find('#ui-nav')
    expect(nav.classes()).toContain('-translate-x-full')
    await w.find('button[aria-label="Open navigation"]').trigger('click')
    expect(w.find('#ui-nav').classes()).toContain('translate-x-0')
    expect(w.find('[data-test="nav-group-warden"] .icon-\\[mdi--key-variant\\]').exists()).toBe(true)
    expect(w.find('[data-test="nav-ops"]').exists()).toBe(true)
    expect(w.find('[style]').exists()).toBe(false)
    await w.find('[data-test="theme-toggle"]').trigger('click')
    expect(document.documentElement.getAttribute('data-theme')).toBe('freya-dark')
    expect(localStorage.getItem('freya.theme')).toBe('freya-dark')
    await w.find('[data-test="theme-toggle"]').trigger('click')
    expect(document.documentElement.getAttribute('data-theme')).toBe('freya-light')
    w.unmount()
    ;(globalThis as unknown as { __vw: number }).__vw = 1280
    const d = mount(Default, { global: { plugins: [router], stubs: { RouterView: true } } })
    await flushPromises()
    expect(d.find('header').classes()).toContain('sticky')
    expect(d.find('#ui-nav').classes()).toContain('translate-x-0')
    expect(d.find('button[aria-label="Open navigation"]').exists()).toBe(false)
    d.unmount()
  })
})
