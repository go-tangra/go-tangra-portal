import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router'
import { defineComponent, h } from 'vue'
import HelpCenter from '@/views/help/HelpCenter.vue'
import HelpPage from '@/views/help/HelpPage.vue'
import HelpSearch from '@/components/HelpSearch.vue'
import Default from '@/layouts/Default.vue'
import { helpPath, safeSnippet } from '@/api/docs'
import { subscribeEvents } from '@/api/events'
import { useHelp } from '@/stores/help'
import { useSession } from '@/stores/session'

type Handler = (url: URL) => unknown
function fetchMock(handler: Handler): URL[] {
  const calls: URL[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: string) => {
    const url = new URL(input, 'https://localhost')
    calls.push(url)
    const out = handler(url)
    if (out && typeof out === 'object' && 'status' in out) {
      const o = out as { status: number; body?: unknown }
      return new Response(JSON.stringify(o.body ?? {}), { status: o.status })
    }
    return new Response(JSON.stringify(out), { status: 200 })
  }))
  return calls
}

const TREE = {
  modules: [
    { module: 'deployer', title: 'Deployer', icon: 'mdi-rocket-launch-outline', groups: [
      { kind: 'guide', pages: [{ slug: 'overview', title: 'Overview', summary: 'What it does' }, { slug: 'guides/auto-deploy', title: 'Auto-deploy to BIG-IP' }] },
      { kind: 'faq', pages: [{ slug: 'faq/rollback', title: 'Why did it roll back?' }] },
    ] },
    { module: 'lcm', title: 'LCM', groups: [{ kind: 'guide', pages: [{ slug: 'renewal', title: 'Renewal windows' }] }] },
  ],
}
const hit = (module: string, slug: string, title: string, kind = 'guide', snippet = '…<mark>deploy</mark> the cert…') =>
  ({ module, module_title: module === 'lcm' ? 'LCM' : 'Deployer', slug, title, kind, snippet, rank: 0.5 })
const searchPage = (extra: Record<string, unknown> = {}) => ({
  items: [hit('deployer', 'guides/auto-deploy', 'Auto-deploy to BIG-IP'), hit('lcm', 'renewal', 'Renewal windows', 'guide', 'x <b>bold</b> <mark>y</mark> &amp; z')],
  total: 16, page: 1, page_size: 10, sort: 'rank', order: 'desc',
  facets: { modules: { deployer: 9, lcm: 4 }, kinds: { guide: 12, faq: 4 } }, fuzzy: false, ...extra,
})
const PAGE = {
  module: 'deployer', module_title: 'Deployer', slug: 'guides/auto-deploy', title: 'Auto-deploy to BIG-IP', summary: 'Push certificates', kind: 'guide', tags: [],
  html: '<h2 id="how-it-works">How it works</h2><p>See <a href="/help/lcm/renewal">renewal</a>.</p><pre class="chroma"><code>x</code></pre>',
  outline: [{ id: 'how-it-works', text: 'How it works', level: 2 }],
  prev: { slug: 'overview', title: 'Overview' }, next: null, version: '4.8.0',
}

const Blank = defineComponent({ render: () => h('div', { 'data-test': 'elsewhere' }) })
function makeRouter(): Router {
  return createRouter({ history: createMemoryHistory(), routes: [
    { path: '/help', name: 'help', component: HelpCenter },
    { path: '/help/:module/:slug(.*)*', name: 'help-page', component: HelpPage },
    { path: '/:p(.*)*', component: Blank },
  ] })
}
async function mountAt(path: string) {
  const router = makeRouter()
  await router.push(path)
  await router.isReady()
  const w = mount(RouterView, { global: { plugins: [router] }, attachTo: document.body })
  await flushPromises()
  return { w, router }
}

describe('help center helpers', () => {
  it('keeps only <mark> from a snippet', () => {
    expect(safeSnippet('a <mark>b</mark> &lt;i&gt; <img src=x onerror=alert(1)> <script>x</script>')).toBe('a <mark>b</mark> &lt;i&gt; &lt;img src=x onerror=alert(1)&gt; &lt;script&gt;x&lt;/script&gt;')
    expect(safeSnippet('<mark onclick="x">b</mark>')).toBe('&lt;mark onclick="x"&gt;b</mark>')
  })
  it('builds help routes with encoded slug segments', () => {
    expect(helpPath('deployer', 'guides/auto deploy', '#x')).toBe('/help/deployer/guides/auto%20deploy#x')
  })
})

describe('help center search', () => {
  beforeEach(() => setActivePinia(createPinia()))
  afterEach(() => {
    vi.useRealTimers()
    document.body.innerHTML = ''
  })

  it('reads the search from the URL, shows facets with counts and ranked hits', async () => {
    const calls = fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : searchPage()))
    const { w } = await mountAt('/help?q=deploy%20cert&module=deployer&kind=guide&page=2')
    const s = calls.find((c) => c.pathname === '/gateway/v1/docs/search')!
    expect(Object.fromEntries(s.searchParams)).toEqual({ q: 'deploy cert', module: 'deployer', kind: 'guide', page: '2', page_size: '10' })
    expect((w.find('[data-test="help-q"]').element as HTMLInputElement).value).toBe('deploy cert')
    expect(w.find('[data-test="facet-module-deployer"]').text()).toBe('Deployer · 9')
    expect(w.find('[data-test="facet-module-deployer"]').attributes('aria-pressed')).toBe('true')
    expect(w.find('[data-test="facet-module-all"]').attributes('aria-pressed')).toBe('false')
    expect(w.find('[data-test="facet-kind-faq"]').text()).toBe('FAQ · 4')
    expect(w.find('[data-test="facet-kind-reference"]').exists()).toBe(false)
    expect(w.find('[data-test="help-count"]').text()).toContain('16 results · ranked by relevance')
    const first = w.find('[data-test="hit-deployer-guides/auto-deploy"]')
    expect(first.find('a').attributes('href')).toBe('/help/deployer/guides/auto-deploy')
    expect(first.text()).toContain('Deployer')
    expect(first.find('mark').text()).toBe('deploy')
    // a tag other than <mark> in a snippet renders as text
    const second = w.find('[data-test="hit-lcm-renewal"] [data-test="hit-snippet"]')
    expect(second.find('b').exists()).toBe(false)
    expect(second.text()).toContain('<b>bold</b>')
    expect(w.find('[data-test="help-modules"]').text()).toContain('Deployer')
    expect(w.find('[data-test="help-permissions"]').exists()).toBe(true)
    w.unmount()
  })

  it('writes facets and pages to the URL and refetches', async () => {
    const calls = fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : searchPage()))
    const { w, router } = await mountAt('/help?q=deploy&page=3')
    await w.find('[data-test="facet-module-lcm"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ q: 'deploy', module: 'lcm' })
    await w.find('[data-test="facet-kind-faq"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ q: 'deploy', module: 'lcm', kind: 'faq' })
    await w.find('[data-test="facet-module-lcm"]').trigger('click') // toggles off
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ q: 'deploy', kind: 'faq' })
    await w.find('button[aria-label="Page 2"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ q: 'deploy', kind: 'faq', page: '2' })
    const last = calls.filter((c) => c.pathname.endsWith('/search')).at(-1)!
    expect(last.searchParams.get('page')).toBe('2')
    expect(last.searchParams.get('kind')).toBe('faq')
    await w.find('select').setValue('20')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ q: 'deploy', kind: 'faq', size: '20' })
    w.unmount()
  })

  it('debounces typing into the URL; Enter commits at once', async () => {
    fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : searchPage()))
    const { w, router } = await mountAt('/help?q=old&page=2')
    vi.useFakeTimers()
    await w.find('[data-test="help-q"]').setValue('cert')
    expect(router.currentRoute.value.query.q).toBe('old')
    vi.advanceTimersByTime(350)
    vi.useRealTimers()
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ q: 'cert' })
    await w.find('[data-test="help-q"]').setValue('bigip')
    await w.find('[data-test="help-search-form"]').trigger('submit')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ q: 'bigip' })
    w.unmount()
  })

  it('shows the fuzzy notice, the empty state and validation errors', async () => {
    let answer: unknown = searchPage({ fuzzy: true })
    fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : answer))
    const { w, router } = await mountAt('/help?q=dploy')
    expect(w.find('[data-test="help-fuzzy"]').exists()).toBe(true)
    expect(w.find('[data-test="help-count"]').text()).not.toContain('ranked')
    answer = searchPage({ items: [], total: 0 })
    await router.push('/help?q=zzz')
    await flushPromises()
    expect(w.find('[data-test="help-empty"]').exists()).toBe(true)
    answer = { status: 400, body: { reason: 'validation_failed', detail: { param: 'q' } } }
    await router.push('/help?q=' + 'x'.repeat(300))
    await flushPromises()
    expect(w.find('[data-test="help-invalid"]').text()).toContain('256')
    answer = { status: 500, body: {} }
    await router.push('/help?q=boom')
    await flushPromises()
    expect(w.find('[data-test="help-error"]').exists()).toBe(true)
    w.unmount()
  })

  it('browses the tree without a query and refetches it on docs_updated', async () => {
    let tree = TREE
    const calls = fetchMock(() => tree)
    const { w } = await mountAt('/help')
    expect(calls.some((c) => c.pathname.endsWith('/search'))).toBe(false)
    const card = w.find('[data-test="browse-deployer"]')
    expect(card.text()).toContain('3 pages')
    expect(card.text()).toContain('FAQ')
    expect(card.find('a[href="/help/deployer/faq/rollback"]').exists()).toBe(true)
    tree = { modules: [TREE.modules[1]!] } as typeof TREE
    useHelp().invalidate('deployer')
    await flushPromises()
    expect(w.find('[data-test="browse-deployer"]').exists()).toBe(false)
    expect(w.find('[data-test="browse-lcm"]').exists()).toBe(true)
    w.unmount()
  })
})

describe('help page', () => {
  beforeEach(() => setActivePinia(createPinia()))
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('renders the page with its TOC, breadcrumb, version, outline and prev link', async () => {
    const calls = fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : PAGE))
    const { w } = await mountAt('/help/deployer/guides/auto-deploy')
    expect(calls.some((c) => c.pathname === '/gateway/v1/docs/deployer/guides/auto-deploy')).toBe(true)
    expect(w.find('[data-test="help-title"]').text()).toBe('Auto-deploy to BIG-IP')
    expect(w.find('[data-test="help-version"]').text()).toBe('deployer 4.8.0')
    expect(w.find('.ui-doc-content h2#how-it-works').exists()).toBe(true)
    expect(w.find('.ui-doc-copy').exists()).toBe(true)
    const current = w.find('[data-test="help-toc"] [aria-current="page"]')
    expect(current.text()).toBe('Auto-deploy to BIG-IP')
    expect(w.findAll('[data-test="help-toc"] [aria-current]')).toHaveLength(1)
    expect(w.find('[data-test="help-outline"]').text()).toContain('How it works')
    expect(w.find('[data-test="help-outline"] a[aria-current="location"]').attributes('href')).toBe('#how-it-works')
    expect(w.find('[data-test="help-prev"]').attributes('href')).toBe('/help/deployer/overview')
    expect(w.find('[data-test="help-next"]').exists()).toBe(false)
    w.unmount()
  })

  it('routes help links inside the page through the router', async () => {
    fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : u.pathname.endsWith('/renewal') ? { ...PAGE, module: 'lcm', module_title: 'LCM', slug: 'renewal', title: 'Renewal windows', prev: null } : PAGE))
    const { w, router } = await mountAt('/help/deployer/guides/auto-deploy')
    w.find('.ui-doc-content a[href="/help/lcm/renewal"]').element.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }))
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/help/lcm/renewal')
    expect(w.find('[data-test="help-title"]').text()).toBe('Renewal windows')
    w.unmount()
  })

  it('shows a friendly not-found for a missing or hidden page', async () => {
    fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : { status: 404, body: { reason: 'not_found' } }))
    const { w } = await mountAt('/help/deployer/secret')
    expect(w.find('[data-test="help-notfound"]').text()).toContain('Help page not found')
    expect(w.find('[data-test="help-notfound"] a').attributes('href')).toBe('/help')
    w.unmount()
  })

  it('opens the first page of a module without a slug', async () => {
    fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : PAGE))
    const { w, router } = await mountAt('/help/deployer')
    expect(router.currentRoute.value.fullPath).toBe('/help/deployer/overview')
    w.unmount()
  })

  it('refetches the shown page when its module documentation changes', async () => {
    let title = 'Before'
    const calls = fetchMock((u) => (u.pathname.endsWith('/tree') ? TREE : { ...PAGE, title }))
    const { w } = await mountAt('/help/deployer/guides/auto-deploy')
    expect(w.find('[data-test="help-title"]').text()).toBe('Before')
    title = 'After'
    useHelp().invalidate('lcm') // another module: nothing refetched
    await flushPromises()
    expect(w.find('[data-test="help-title"]').text()).toBe('Before')
    useHelp().invalidate('deployer')
    await flushPromises()
    expect(w.find('[data-test="help-title"]').text()).toBe('After')
    expect(calls.filter((c) => c.pathname.endsWith('/auto-deploy'))).toHaveLength(2)
    w.unmount()
  })
})

describe('quick search (app bar)', () => {
  beforeEach(() => setActivePinia(createPinia()))
  afterEach(() => {
    document.body.innerHTML = ''
    document.body.className = ''
  })

  async function setup() {
    const calls = fetchMock(() => searchPage())
    const router = makeRouter()
    await router.push('/')
    const w = mount(HelpSearch, { global: { plugins: [router] }, attachTo: document.body })
    return { w, router, calls }
  }
  const key = (k: string, init: KeyboardEventInit = {}) => document.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...init }))

  it('opens on Ctrl+K and Cmd+K with the focus in a labelled search box', async () => {
    const { w } = await setup()
    expect(document.querySelector('[data-test="help-quick"]')).toBeNull()
    key('k', { ctrlKey: true })
    await flushPromises()
    const input = document.querySelector<HTMLInputElement>('[data-test="help-quick-q"]')!
    expect(input).not.toBeNull()
    expect(document.activeElement).toBe(input)
    expect(document.querySelector('label[for="help-quick-q"]')?.textContent).toBe('Search documentation')
    key('Escape')
    await flushPromises()
    expect(document.querySelector('[data-test="help-quick"]')).toBeNull()
    key('k', { metaKey: true })
    await flushPromises()
    expect(document.querySelector('[data-test="help-quick"]')).not.toBeNull()
    w.unmount()
  })

  it('lists the top hits, moves with the arrows and opens the chosen page', async () => {
    const { w, router, calls } = await setup()
    await w.find('[data-test="help-search"]').trigger('click')
    await flushPromises()
    const input = document.querySelector<HTMLInputElement>('[data-test="help-quick-q"]')!
    vi.useFakeTimers()
    input.value = 'deploy'
    input.dispatchEvent(new Event('input'))
    vi.advanceTimersByTime(250)
    vi.useRealTimers()
    await flushPromises()
    expect(calls.at(-1)!.searchParams.get('page_size')).toBe('6')
    const options = document.querySelectorAll('[role="option"]')
    expect(options).toHaveLength(2)
    const press = (k: string) => input.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }))
    press('ArrowDown')
    press('ArrowDown')
    await flushPromises()
    expect(input.getAttribute('aria-activedescendant')).toBe('help-quick-opt-1')
    expect(document.getElementById('help-quick-opt-1')?.getAttribute('aria-selected')).toBe('true')
    press('ArrowDown') // wraps
    await flushPromises()
    expect(input.getAttribute('aria-activedescendant')).toBe('help-quick-opt-0')
    press('Enter')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/help/deployer/guides/auto-deploy')
    expect(document.querySelector('[data-test="help-quick"]')).toBeNull()
    w.unmount()
  })

  it('Enter without a chosen hit opens the full results page', async () => {
    const { w, router } = await setup()
    key('k', { ctrlKey: true })
    await flushPromises()
    const input = document.querySelector<HTMLInputElement>('[data-test="help-quick-q"]')!
    input.value = 'bigip f5'
    input.dispatchEvent(new Event('input'))
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }))
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/help?q=bigip%20f5')
    w.unmount()
  })
})

describe('help in the shell frame', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('puts the help center below the modules and above operations, and the search in the app bar', async () => {
    const s = useSession()
    s.apply({ user_id: 'u1', tenant_id: 't1', operator: true })
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
      { module: 'warden', display_name: 'Warden', nav: [{ title: 'Secrets', path: '/warden', order: 100 }] },
    ]), { status: 200 })))
    await s.loadModules()
    const router = makeRouter()
    await router.push('/')
    const w = mount(Default, { slots: { default: '<p>content</p>' }, global: { plugins: [router] } })
    await flushPromises()
    const order = w.findAll('[data-test^="nav-"]').map((n) => n.attributes('data-test')).filter((t) => ['nav-home', 'nav-group-warden', 'nav-help', 'nav-ops'].includes(t!))
    expect(order).toEqual(['nav-home', 'nav-group-warden', 'nav-help', 'nav-ops'])
    expect(w.find('[data-test="nav-help"]').attributes('href')).toBe('/help')
    expect(w.find('[data-test="nav-help"] .icon-\\[mdi--help-circle-outline\\]').exists()).toBe(true)
    expect(w.find('[data-test="help-search"]').attributes('aria-label')).toMatch(/^Search documentation \((Ctrl\+K|⌘K)\)$/)
    w.unmount()
  })
})

describe('docs_updated event', () => {
  it('reaches onDocs with the module', () => {
    const listeners: Record<string, (ev: MessageEvent) => void> = {}
    vi.stubGlobal('EventSource', class { onerror = null; onopen = null; addEventListener(t: string, fn: (ev: MessageEvent) => void) { listeners[t] = fn } close() {} })
    const onDocs = vi.fn()
    const stop = subscribeEvents({ onDocs })
    listeners.docs_updated!(new MessageEvent('docs_updated', { data: '{"module":"deployer"}' }))
    listeners.docs_updated!(new MessageEvent('docs_updated', { data: 'garbage' }))
    listeners.docs_updated!(new MessageEvent('docs_updated', { data: '{"module":""}' }))
    expect(onDocs.mock.calls).toEqual([['deployer']])
    stop()
  })
})
