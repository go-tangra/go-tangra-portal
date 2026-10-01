// One server-paged table: page/size/sort in the URL (kit useListQuery), the
// current page of rows, its total, and reloads whenever the query changes.
// Filters are read through `filters()` and applied with `search()`, which
// returns to page 1.
import { ref, watch, type Ref } from 'vue'
import { useListQuery, type ListQueryOptions } from '@go-tangra/ui'
import { api, ApiError } from '@/api/client'

/** The list contract response (go-tangra specs/032-server-side-tables). */
export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  sort: string
  order: 'asc' | 'desc'
}

export function useServerList<T>(key: string, path: string, opts: ListQueryOptions, filters: () => Record<string, string | undefined> = () => ({})) {
  const lq = useListQuery(key, opts)
  const items = ref([]) as Ref<T[]>
  const total = ref(0)
  const loading = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const res = await lq.track(api<Page<T>>('GET', path, undefined, { query: { ...filters(), ...lq.query.value } }))
      if (!res) return // superseded by a newer request
      items.value = res.items
      total.value = res.total
      lq.clampTo(res.page)
    } catch (err) {
      error.value = err instanceof ApiError ? err.reason : 'error'
    } finally {
      loading.value = false
    }
  }

  /** Apply changed filters: back to page 1 (which reloads), or reload in place. */
  function search(): void {
    if (lq.page.value !== 1) lq.resetPage()
    else void load()
  }

  watch(lq.query, () => void load())
  return { lq, items, total, loading, error, load, search }
}
