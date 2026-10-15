<script setup lang="ts">
// One help page: the module's table of contents (left), the rendered page
// (centre, UiDocContent) and its outline with scroll-spy (right).
// /help/<module> without a slug opens the module's first page.
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { UiBadge, UiCard, UiDocContent, UiEmptyState, UiErrorState, UiIcon, UiSkeleton } from '@go-tangra/ui'
import { ApiError } from '@/api/client'
import { helpPath, kindColor, kindLabel, type DocPage, type DocsTree } from '@/api/docs'
import { useHelp } from '@/stores/help'

const route = useRoute()
const router = useRouter()
const help = useHelp()

const moduleName = computed(() => String(route.params.module ?? ''))
const slug = computed(() => {
  const s = route.params.slug
  return (Array.isArray(s) ? s.join('/') : String(s ?? '')).replace(/\/+$/, '')
})

const page = ref<DocPage | null>(null)
const state = ref<'loading' | 'ok' | 'notfound' | 'error'>('loading')
const errorText = ref('')
let seq = 0

async function load(force = false): Promise<void> {
  const my = ++seq
  const m = moduleName.value
  if (!slug.value) {
    // Module landing: its first page.
    try {
      const t = await help.loadTree()
      if (my !== seq) return
      const first = t.modules.find((x) => x.module === m)?.groups.find((g) => g.pages.length)?.pages[0]
      if (first) {
        void router.replace(helpPath(m, first.slug))
        return
      }
    } catch {
      /* fall through to not found */
    }
    if (my === seq) state.value = 'notfound'
    return
  }
  if (!page.value || page.value.module !== m || page.value.slug !== slug.value) state.value = 'loading'
  try {
    const p = await help.loadPage(m, slug.value, force)
    if (my !== seq) return
    page.value = p
    state.value = 'ok'
  } catch (e) {
    if (my !== seq) return
    if (e instanceof ApiError && e.status === 404) {
      state.value = 'notfound'
    } else {
      state.value = 'error'
      errorText.value = e instanceof ApiError && (e.reason === 'network' || e.reason === 'temporarily_unavailable') ? 'The help center is unreachable right now.' : 'The page could not be loaded.'
    }
  }
}
watch([moduleName, slug], () => void load(), { immediate: true })
// docs_updated for this module: refetch what is shown.
watch(() => help.revisions[moduleName.value] ?? 0, (n, o) => {
  if (n !== o) void load(true)
})

const tree = ref<DocsTree | null>(null)
async function loadTree(): Promise<void> {
  try {
    tree.value = await help.loadTree()
  } catch {
    tree.value = null // the page still shows without its table of contents
  }
}
watch(() => help.revision, () => void loadTree(), { immediate: true })
const toc = computed(() => tree.value?.modules.find((m) => m.module === moduleName.value) ?? null)

// Links inside the page: help links go through the router, anchors stay on the page.
const doc = ref<{ scrollTo: (hash: string) => void } | null>(null)
function onNavigate(to: string): void {
  if (to.startsWith('#')) void router.replace({ hash: to })
  else void router.push(to)
}
function goTo(id: string): void {
  void router.replace({ hash: '#' + id })
  doc.value?.scrollTo(id)
  active.value = id
}

// Scroll-spy: the outline marks the last heading that crossed the top band.
const content = ref<HTMLElement | null>(null)
const active = ref('')
let observer: IntersectionObserver | null = null
function spy(): void {
  observer?.disconnect()
  observer = null
  const fromHash = decodeURIComponent(route.hash.replace(/^#/, ''))
  active.value = page.value?.outline.find((h) => h.id === fromHash)?.id ?? page.value?.outline[0]?.id ?? ''
  if (!content.value || typeof IntersectionObserver === 'undefined' || !page.value) return
  const ids = new Set(page.value.outline.map((h) => h.id))
  const heads = Array.from(content.value.querySelectorAll<HTMLElement>('h2[id], h3[id]')).filter((h) => ids.has(h.id))
  observer = new IntersectionObserver((entries) => {
    const hit = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0]
    if (hit) active.value = hit.target.id
  }, { rootMargin: '-80px 0px -70% 0px' })
  for (const h of heads) observer.observe(h)
}
watch(page, async () => {
  await nextTick()
  spy()
})
onBeforeUnmount(() => observer?.disconnect())
</script>

<template>
  <div class="grid gap-6 lg:grid-cols-[14rem_minmax(0,1fr)] xl:grid-cols-[14rem_minmax(0,1fr)_13rem]">
    <!-- Module table of contents. -->
    <nav v-if="toc" class="lg:sticky lg:top-24 lg:self-start" :aria-label="toc.title + ' documentation'" data-test="help-toc">
      <RouterLink to="/help" class="link link-hover text-base-content/70 mb-3 inline-flex items-center gap-1 text-sm"><UiIcon name="mdi-arrow-left" size="xs" />Help center</RouterLink>
      <div class="mb-3 flex items-center gap-2 font-semibold">
        <UiIcon :name="toc.icon || 'mdi-book-open-page-variant-outline'" size="sm" class="text-primary" />{{ toc.title }}
      </div>
      <div v-for="g in toc.groups" :key="g.kind" class="mb-4">
        <h2 class="text-base-content/70 mb-1 px-2 text-xs font-medium uppercase tracking-wide">{{ kindLabel(g.kind, true) }}</h2>
        <ul class="menu menu-sm w-full p-0">
          <li v-for="p in g.pages" :key="p.slug">
            <RouterLink :to="helpPath(toc.module, p.slug)" :class="p.slug === slug ? 'menu-active' : ''" :aria-current="p.slug === slug ? 'page' : undefined" :data-test="'toc-' + p.slug">{{ p.title }}</RouterLink>
          </li>
        </ul>
      </div>
    </nav>
    <div v-else class="max-lg:hidden" />

    <div class="min-w-0">
      <UiSkeleton v-if="state === 'loading'" kind="card" :lines="8" />
      <UiCard v-else-if="state === 'notfound'" data-test="help-notfound">
        <UiEmptyState title="Help page not found" text="It may have moved or been removed, or it belongs to a module or area you cannot access." icon="mdi-file-search-outline">
          <RouterLink to="/help" class="btn btn-primary btn-sm">Go to the help center</RouterLink>
        </UiEmptyState>
      </UiCard>
      <UiErrorState v-else-if="state === 'error'" title="Help page unavailable" :text="errorText" data-test="help-page-error" @retry="load(true)" />
      <UiCard v-else-if="page" data-test="help-page">
        <div class="flex flex-wrap items-center gap-2 text-xs">
          <nav aria-label="Breadcrumb" class="text-base-content/70">
            <ol class="flex flex-wrap items-center gap-1">
              <li><RouterLink to="/help" class="link link-hover">Help center</RouterLink></li>
              <li aria-hidden="true"><UiIcon name="mdi-chevron-right" size="xs" /></li>
              <li><RouterLink :to="'/help/' + encodeURIComponent(page.module)" class="link link-hover">{{ page.module_title }}</RouterLink></li>
              <li aria-hidden="true"><UiIcon name="mdi-chevron-right" size="xs" /></li>
              <li>{{ kindLabel(page.kind, true) }}</li>
            </ol>
          </nav>
          <UiBadge :color="kindColor(page.kind)" size="xs">{{ kindLabel(page.kind) }}</UiBadge>
          <span v-if="page.version" class="text-base-content/70 ms-auto" data-test="help-version">{{ page.module }} {{ page.version }}</span>
        </div>
        <header>
          <h1 class="text-2xl font-bold leading-tight sm:text-3xl" data-test="help-title">{{ page.title }}</h1>
          <p v-if="page.summary" class="text-base-content/70 mt-2">{{ page.summary }}</p>
        </header>
        <div ref="content">
          <UiDocContent ref="doc" :html="page.html" :hash="route.hash" :label="page.title" @navigate="onNavigate" />
        </div>
        <nav v-if="page.prev?.slug || page.next?.slug" aria-label="Previous and next page" class="border-base-300 flex flex-wrap justify-between gap-4 border-t pt-4 text-sm">
          <RouterLink v-if="page.prev?.slug" :to="helpPath(page.module, page.prev.slug)" class="link link-hover inline-flex items-center gap-1" data-test="help-prev"><UiIcon name="mdi-chevron-left" size="sm" />{{ page.prev.title }}</RouterLink>
          <span v-else />
          <RouterLink v-if="page.next?.slug" :to="helpPath(page.module, page.next.slug)" class="link link-hover link-primary inline-flex items-center gap-1" data-test="help-next">{{ page.next.title }}<UiIcon name="mdi-chevron-right" size="sm" /></RouterLink>
        </nav>
      </UiCard>
    </div>

    <!-- On this page. -->
    <nav v-if="state === 'ok' && page && page.outline.length" class="max-xl:hidden xl:sticky xl:top-24 xl:self-start" aria-labelledby="help-outline" data-test="help-outline">
      <h2 id="help-outline" class="mb-2 text-sm font-semibold">On this page</h2>
      <ul class="border-base-300 space-y-1 border-s text-sm">
        <li v-for="h in page.outline" :key="h.id">
          <a
            :href="'#' + h.id"
            class="-ms-px block border-s-2 py-0.5 hover:text-base-content"
            :class="[h.level > 2 ? 'ps-6' : 'ps-3', active === h.id ? 'border-primary text-primary' : 'text-base-content/70 border-transparent']"
            :aria-current="active === h.id ? 'location' : undefined"
            @click.prevent="goTo(h.id)"
          >{{ h.text }}</a>
        </li>
      </ul>
    </nav>
  </div>
</template>
