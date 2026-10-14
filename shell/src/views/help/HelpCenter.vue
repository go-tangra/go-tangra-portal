<script setup lang="ts">
// Help center: full-text search over the module documentation the caller may
// see (query, filters and page live in the URL: ?q=&module=&kind=&page=&size=),
// and, without a query, the browse view of every module's pages.
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter, type LocationQueryRaw } from 'vue-router'
import { UiAlert, UiBadge, UiCard, UiEmptyState, UiErrorState, UiIcon, UiPage, UiPager, UiSkeleton } from '@go-tangra/ui'
import { ApiError } from '@/api/client'
import { DOC_KINDS, helpPath, isKind, kindColor, kindLabel, safeSnippet, searchDocs, type DocKind, type DocsSearchPage, type DocsSearchQuery, type DocsTree, type DocsTreeModule } from '@/api/docs'
import { useHelp } from '@/stores/help'

const route = useRoute()
const router = useRouter()
const help = useHelp()

const PAGE_SIZES = [10, 20, 50]
const DEFAULT_SIZE = 10
const DEBOUNCE_MS = 300

const str = (v: unknown): string => (typeof v === 'string' ? v : Array.isArray(v) && typeof v[0] === 'string' ? v[0] : '')
const q = computed(() => str(route.query.q).trim())
const moduleFilter = computed(() => str(route.query.module))
const kindFilter = computed<DocKind | ''>(() => {
  const k = str(route.query.kind)
  return isKind(k) ? k : ''
})
const page = computed(() => Math.max(1, Number.parseInt(str(route.query.page), 10) || 1))
const pageSize = computed(() => {
  const n = Number.parseInt(str(route.query.size), 10)
  return PAGE_SIZES.includes(n) ? n : DEFAULT_SIZE
})

/** Writes the search state to the URL (empty values and defaults are left out). */
function setQuery(patch: { q?: string; module?: string; kind?: string; page?: number; size?: number }, replace = false) {
  const s = { q: q.value, module: moduleFilter.value, kind: kindFilter.value as string, page: page.value, size: pageSize.value, ...patch }
  const query: LocationQueryRaw = {}
  if (s.q) query.q = s.q
  if (s.module) query.module = s.module
  if (s.kind) query.kind = s.kind
  if (s.page > 1) query.page = String(s.page)
  if (s.size !== DEFAULT_SIZE) query.size = String(s.size)
  const to = { name: 'help', query }
  return replace ? router.replace(to) : router.push(to)
}

// The search box: typing updates the URL after a pause (replace, so history
// keeps one entry per search); Enter commits at once.
const text = ref(q.value)
let timer: ReturnType<typeof setTimeout> | undefined
watch(q, (v) => {
  if (v !== text.value.trim()) text.value = v
})
function commit(replace: boolean): void {
  clearTimeout(timer)
  const v = text.value.trim()
  if (v !== q.value) void setQuery({ q: v, page: 1 }, replace)
}
function onInput(e: Event): void {
  text.value = (e.target as HTMLInputElement).value
  clearTimeout(timer)
  timer = setTimeout(() => commit(true), DEBOUNCE_MS)
}
onBeforeUnmount(() => clearTimeout(timer))

const message = (e: unknown): string => {
  if (e instanceof ApiError) {
    if (e.reason === 'validation_failed') return 'That search could not be run. Use fewer than 256 characters.'
    if (e.reason === 'network' || e.reason === 'temporarily_unavailable') return 'The help center is unreachable right now.'
    return 'The request was refused (' + e.reason + ').'
  }
  return 'Something went wrong.'
}

// Search results.
const result = ref<DocsSearchPage | null>(null)
const loading = ref(false)
const error = ref('')
const invalid = ref(false)
let ctrl: AbortController | null = null
async function runSearch(): Promise<void> {
  ctrl?.abort()
  if (!q.value) {
    ctrl = null
    result.value = null
    error.value = ''
    loading.value = false
    return
  }
  const c = new AbortController()
  ctrl = c
  loading.value = true
  error.value = ''
  invalid.value = false
  const query: DocsSearchQuery = { q: q.value, page: page.value, page_size: pageSize.value }
  if (moduleFilter.value) query.module = moduleFilter.value
  if (kindFilter.value) query.kind = kindFilter.value
  try {
    const r = await searchDocs(query, c.signal)
    if (ctrl === c) result.value = r
  } catch (e) {
    if (ctrl !== c) return
    result.value = null
    invalid.value = e instanceof ApiError && e.reason === 'validation_failed'
    error.value = message(e)
  } finally {
    if (ctrl === c) loading.value = false
  }
}
watch([q, moduleFilter, kindFilter, page, pageSize, () => help.revision], () => void runSearch(), { immediate: true })
onBeforeUnmount(() => ctrl?.abort())

// The browse tree (also titles and page counts for the facets and the side panel).
const tree = ref<DocsTree | null>(null)
const treeError = ref('')
async function loadTree(): Promise<void> {
  treeError.value = ''
  try {
    tree.value = await help.loadTree()
  } catch (e) {
    treeError.value = message(e)
  }
}
watch(() => help.revision, () => void loadTree(), { immediate: true })

const modules = computed<DocsTreeModule[]>(() => tree.value?.modules ?? [])
const pageCount = (m: DocsTreeModule): number => m.groups.reduce((n, g) => n + g.pages.length, 0)
const firstPage = (m: DocsTreeModule): string => {
  const p = m.groups.find((g) => g.pages.length)?.pages[0]
  return p ? helpPath(m.module, p.slug) : '/help'
}
const titles = computed(() => {
  const t: Record<string, string> = {}
  for (const m of modules.value) t[m.module] = m.title
  for (const h of result.value?.items ?? []) t[h.module] = h.module_title
  return t
})
const icons = computed(() => Object.fromEntries(modules.value.map((m) => [m.module, m.icon || 'mdi-book-open-page-variant-outline'])))
const titleOf = (m: string): string => titles.value[m] || m

const moduleFacets = computed(() => {
  const f = result.value?.facets.modules ?? {}
  const list = Object.entries(f).sort((a, b) => b[1] - a[1] || titleOf(a[0]).localeCompare(titleOf(b[0])))
  if (moduleFilter.value && !(moduleFilter.value in f)) list.push([moduleFilter.value, 0])
  return list
})
const kindFacets = computed(() => {
  const f = result.value?.facets.kinds ?? {}
  return DOC_KINDS.map((k) => [k, f[k] ?? 0] as const).filter(([k, n]) => n > 0 || k === kindFilter.value)
})
const fmt = (n: number) => n.toLocaleString('en-US')
const chip = (active: boolean) => ['btn btn-sm rounded-full', active ? 'btn-primary' : 'btn-soft']
</script>

<template>
  <UiPage title="Help center" subtitle="Guides, examples and reference for the installed modules">
    <div class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
      <div class="min-w-0 space-y-4">
        <form role="search" class="space-y-3" data-test="help-search-form" @submit.prevent="commit(false)">
          <label for="help-q" class="sr-only">Search documentation</label>
          <div class="input input-lg bg-base-100 flex w-full items-center gap-3">
            <UiIcon name="mdi-magnify" class="text-primary" />
            <input id="help-q" :value="text" type="search" class="grow" placeholder="Search documentation…" autocomplete="off" aria-describedby="help-q-hint" data-test="help-q" @input="onInput">
          </div>
          <p id="help-q-hint" class="text-base-content/70 text-xs">Use "quoted phrases", -exclude and or.</p>
        </form>

        <template v-if="q">
          <div v-if="result" class="flex flex-wrap items-center gap-2" data-test="help-facets">
            <div role="group" aria-label="Filter by module" class="flex flex-wrap gap-2">
              <button type="button" :class="chip(!moduleFilter)" :aria-pressed="!moduleFilter" data-test="facet-module-all" @click="setQuery({ module: '', page: 1 })">All modules</button>
              <button v-for="[m, n] in moduleFacets" :key="m" type="button" :class="chip(moduleFilter === m)" :aria-pressed="moduleFilter === m" :data-test="'facet-module-' + m" @click="setQuery({ module: moduleFilter === m ? '' : m, page: 1 })">{{ titleOf(m) }} · {{ fmt(n) }}</button>
            </div>
            <span class="bg-base-300 mx-1 hidden h-6 w-px sm:block" aria-hidden="true" />
            <div role="group" aria-label="Filter by kind" class="flex flex-wrap gap-2">
              <button type="button" :class="chip(!kindFilter)" :aria-pressed="!kindFilter" data-test="facet-kind-all" @click="setQuery({ kind: '', page: 1 })">Any kind</button>
              <button v-for="[k, n] in kindFacets" :key="k" type="button" :class="chip(kindFilter === k)" :aria-pressed="kindFilter === k" :data-test="'facet-kind-' + k" @click="setQuery({ kind: kindFilter === k ? '' : k, page: 1 })">{{ kindLabel(k, true) }} · {{ fmt(n) }}</button>
            </div>
          </div>

          <UiAlert v-if="invalid" kind="warning" data-test="help-invalid">{{ error }}</UiAlert>
          <UiErrorState v-else-if="error" title="Search failed" :text="error" data-test="help-error" @retry="runSearch" />
          <UiSkeleton v-else-if="loading && !result" kind="card" :lines="3" />
          <template v-else-if="result">
            <UiAlert v-if="result.fuzzy && result.items.length" kind="info" data-test="help-fuzzy">No page contains all of these words; showing pages with similar titles.</UiAlert>
            <p v-if="result.items.length" class="text-base-content/70 text-sm" aria-live="polite" data-test="help-count">
              {{ fmt(result.total) }} {{ result.total === 1 ? 'result' : 'results' }}{{ result.fuzzy ? '' : ' · ranked by relevance' }}
            </p>
            <UiEmptyState v-if="!result.items.length" title="No help pages match" text="Try other words, or remove the module or kind filter." icon="mdi-file-search-outline" data-test="help-empty" />
            <ol v-else class="space-y-3" :aria-busy="loading || undefined" data-test="help-results">
              <li v-for="hit in result.items" :key="hit.module + '/' + hit.slug">
                <UiCard flat :data-test="'hit-' + hit.module + '-' + hit.slug">
                  <div class="space-y-1.5">
                    <div class="text-base-content/70 flex flex-wrap items-center gap-2 text-xs">
                      <UiIcon :name="icons[hit.module] || 'mdi-book-open-page-variant-outline'" size="xs" />
                      <span>{{ hit.module_title }}</span>
                      <UiIcon name="mdi-chevron-right" size="xs" />
                      <span>{{ kindLabel(hit.kind, true) }}</span>
                      <UiBadge :color="kindColor(hit.kind)" size="xs">{{ kindLabel(hit.kind) }}</UiBadge>
                    </div>
                    <h2 class="text-base font-semibold">
                      <RouterLink :to="helpPath(hit.module, hit.slug)" class="link link-hover link-primary">{{ hit.title }}</RouterLink>
                    </h2>
                    <!-- eslint-disable-next-line vue/no-v-html -- gateway-escaped text with <mark> only, re-checked by safeSnippet -->
                    <p class="ui-doc-snippet text-base-content/80 text-sm" data-test="hit-snippet" v-html="safeSnippet(hit.snippet)" />
                  </div>
                </UiCard>
              </li>
            </ol>
            <UiPager v-if="result.items.length" :page="result.page" :page-size="result.page_size" :total="result.total" :page-sizes="PAGE_SIZES" label="Search result pages" @update:page="(p) => setQuery({ page: p })" @update:page-size="(s) => setQuery({ size: s, page: 1 })" />
          </template>
        </template>

        <!-- No query: browse every module's pages. -->
        <section v-else aria-labelledby="help-browse" class="space-y-4" data-test="help-browse">
          <h2 id="help-browse" class="text-lg font-semibold">Browse documentation</h2>
          <UiErrorState v-if="treeError" title="The help pages could not be loaded" :text="treeError" @retry="loadTree" />
          <UiSkeleton v-else-if="!tree" kind="card" :lines="4" />
          <UiEmptyState v-else-if="!modules.length" title="No help pages yet" text="None of the modules you can use ships documentation." icon="mdi-book-open-page-variant-outline" />
          <div v-else class="grid gap-4 md:grid-cols-2">
            <UiCard v-for="m in modules" :key="m.module" flat :data-test="'browse-' + m.module">
              <h3 class="flex items-center gap-2 font-semibold">
                <UiIcon :name="m.icon || 'mdi-book-open-page-variant-outline'" size="sm" class="text-primary" />
                <RouterLink :to="firstPage(m)" class="link link-hover">{{ m.title }}</RouterLink>
                <span class="text-base-content/70 ms-auto text-xs font-normal">{{ pageCount(m) }} {{ pageCount(m) === 1 ? 'page' : 'pages' }}</span>
              </h3>
              <div v-for="g in m.groups" :key="g.kind">
                <h4 class="text-base-content/70 mb-1 text-xs font-medium uppercase tracking-wide">{{ kindLabel(g.kind, true) }}</h4>
                <ul class="space-y-1 text-sm">
                  <li v-for="p in g.pages" :key="p.slug">
                    <RouterLink :to="helpPath(m.module, p.slug)" class="link link-hover link-primary">{{ p.title }}</RouterLink>
                    <span v-if="p.summary" class="text-base-content/70"> — {{ p.summary }}</span>
                  </li>
                </ul>
              </div>
            </UiCard>
          </div>
        </section>
      </div>

      <aside class="space-y-4" aria-label="Help center">
        <UiCard v-if="q && modules.length" title="Browse installed modules" flat data-test="help-modules">
          <ul class="space-y-1 text-sm">
            <li v-for="m in modules" :key="m.module" class="flex items-center gap-2">
              <UiIcon :name="m.icon || 'mdi-book-open-page-variant-outline'" size="sm" class="text-base-content/70" />
              <RouterLink :to="firstPage(m)" class="link link-hover grow truncate">{{ m.title }}</RouterLink>
              <span class="text-base-content/70 text-xs">{{ pageCount(m) }}</span>
            </li>
          </ul>
        </UiCard>
        <UiCard flat data-test="help-permissions">
          <h2 class="flex items-center gap-2 text-sm font-semibold"><UiIcon name="mdi-lock-outline" size="sm" />Filtered by your permissions</h2>
          <p class="text-base-content/70 text-sm">Results, pages and counts only include the documentation of modules and areas you can access.</p>
        </UiCard>
      </aside>
    </div>
  </UiPage>
</template>
