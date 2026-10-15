<script setup lang="ts">
// App-bar documentation search. Ctrl/Cmd+K (or the button) opens a dialog with
// the top hits as you type; arrows move through them, Enter opens the chosen
// one, or the full results page (/help?q=) when none is chosen.
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { UiDialog, UiIcon, UiBadge } from '@go-tangra/ui'
import { helpPath, kindColor, kindLabel, safeSnippet, searchDocs, type DocsSearchPage } from '@/api/docs'

const LIMIT = 6
const DEBOUNCE_MS = 200

const router = useRouter()
const open = ref(false)
const text = ref('')
const result = ref<DocsSearchPage | null>(null)
const loading = ref(false)
const failed = ref(false)
const activeIndex = ref(-1)
const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)
const shortcut = isMac ? '⌘K' : 'Ctrl+K'

const items = computed(() => result.value?.items ?? [])
const optionId = (i: number) => 'help-quick-opt-' + i

let timer: ReturnType<typeof setTimeout> | undefined
let ctrl: AbortController | null = null
async function search(): Promise<void> {
  ctrl?.abort()
  const q = text.value.trim()
  activeIndex.value = -1
  if (!q) {
    ctrl = null
    result.value = null
    loading.value = false
    failed.value = false
    return
  }
  const c = new AbortController()
  ctrl = c
  loading.value = true
  try {
    const r = await searchDocs({ q, page_size: LIMIT }, c.signal)
    if (ctrl !== c) return
    result.value = r
    failed.value = false
  } catch {
    if (ctrl !== c) return
    result.value = null
    failed.value = true
  } finally {
    if (ctrl === c) loading.value = false
  }
}
function onInput(e: Event): void {
  text.value = (e.target as HTMLInputElement).value
  clearTimeout(timer)
  timer = setTimeout(() => void search(), DEBOUNCE_MS)
}

function go(path: string): void {
  open.value = false
  void router.push(path)
}
function fullResults(): void {
  const q = text.value.trim()
  go(q ? '/help?q=' + encodeURIComponent(q) : '/help')
}
function onKey(e: KeyboardEvent): void {
  const n = items.value.length
  if (e.key === 'ArrowDown' && n) {
    e.preventDefault()
    activeIndex.value = (activeIndex.value + 1) % n
  } else if (e.key === 'ArrowUp' && n) {
    e.preventDefault()
    activeIndex.value = activeIndex.value <= 0 ? n - 1 : activeIndex.value - 1
  } else if (e.key === 'Enter') {
    e.preventDefault()
    const hit = items.value[activeIndex.value]
    if (hit) go(helpPath(hit.module, hit.slug))
    else fullResults()
  }
}

// Ctrl/Cmd+K anywhere opens the dialog (and wins over the browser's own binding).
function onShortcut(e: KeyboardEvent): void {
  if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    open.value = true
  }
}
onMounted(() => document.addEventListener('keydown', onShortcut))
onBeforeUnmount(() => {
  document.removeEventListener('keydown', onShortcut)
  clearTimeout(timer)
  ctrl?.abort()
})
watch(open, (o) => {
  if (!o) {
    clearTimeout(timer)
    ctrl?.abort()
    loading.value = false
  }
})
</script>

<template>
  <button type="button" class="btn btn-soft btn-sm gap-2 font-normal md:w-56 md:justify-start lg:w-72" :aria-label="'Search documentation (' + shortcut + ')'" aria-haspopup="dialog" data-test="help-search" @click="open = true">
    <UiIcon name="mdi-magnify" size="sm" />
    <span class="text-base-content/70 max-md:sr-only">Search documentation…</span>
    <kbd class="kbd kbd-sm ms-auto max-md:hidden" aria-hidden="true">{{ shortcut }}</kbd>
  </button>
  <UiDialog v-model="open" title="Search documentation" size="md" data-test="help-quick">
    <div class="space-y-3">
      <label for="help-quick-q" class="sr-only">Search documentation</label>
      <div class="input flex w-full items-center gap-2">
        <UiIcon name="mdi-magnify" size="sm" class="text-primary" />
        <input
          id="help-quick-q"
          :value="text"
          type="search"
          class="grow"
          placeholder="Search documentation…"
          autocomplete="off"
          role="combobox"
          aria-autocomplete="list"
          aria-controls="help-quick-list"
          :aria-expanded="items.length > 0"
          :aria-activedescendant="activeIndex >= 0 ? optionId(activeIndex) : undefined"
          data-test="help-quick-q"
          @input="onInput"
          @keydown="onKey"
        >
        <span v-if="loading" class="loading loading-spinner loading-xs" aria-hidden="true" />
      </div>
      <p v-if="failed" class="text-error text-sm" role="alert">The search could not be run.</p>
      <p v-else-if="result && !items.length" class="text-base-content/70 text-sm" data-test="help-quick-empty">No help pages match.</p>
      <p v-else-if="result?.fuzzy" class="text-base-content/70 text-xs">No exact matches; similar titles:</p>
      <ul v-if="items.length" id="help-quick-list" role="listbox" aria-label="Top results" class="space-y-1" data-test="help-quick-list">
        <li
          v-for="(hit, i) in items"
          :id="optionId(i)"
          :key="hit.module + '/' + hit.slug"
          role="option"
          :aria-selected="i === activeIndex"
          class="rounded-field cursor-pointer px-3 py-2"
          :class="i === activeIndex ? 'bg-primary/10' : 'hover:bg-base-200'"
          :data-test="'help-quick-' + i"
          @mousedown.prevent
          @mouseenter="activeIndex = i"
          @click="go(helpPath(hit.module, hit.slug))"
        >
          <div class="flex items-center gap-2">
            <span class="grow truncate font-medium">{{ hit.title }}</span>
            <UiBadge :color="kindColor(hit.kind)" size="xs">{{ kindLabel(hit.kind) }}</UiBadge>
          </div>
          <div class="text-base-content/70 truncate text-xs">{{ hit.module_title }}</div>
          <!-- eslint-disable-next-line vue/no-v-html -- gateway-escaped text with <mark> only, re-checked by safeSnippet -->
          <div class="ui-doc-snippet text-base-content/70 line-clamp-1 text-xs" v-html="safeSnippet(hit.snippet)" />
        </li>
      </ul>
    </div>
    <template #actions>
      <span class="text-base-content/70 me-auto hidden items-center gap-1 text-xs sm:inline-flex"><kbd class="kbd kbd-xs">↑</kbd><kbd class="kbd kbd-xs">↓</kbd> to choose, <kbd class="kbd kbd-xs"><UiIcon name="mdi-keyboard-return" size="xs" /></kbd> to open</span>
      <button type="button" class="btn btn-soft btn-primary btn-sm" data-test="help-quick-all" @click="fullResults">{{ text.trim() ? 'See all results' : 'Open the help center' }}</button>
    </template>
  </UiDialog>
</template>
