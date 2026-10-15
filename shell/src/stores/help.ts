import { defineStore } from 'pinia'
import { fetchDocPage, fetchDocsTree, type DocPage, type DocsTree } from '@/api/docs'

let treeInFlight: Promise<DocsTree> | null = null

/**
 * Cached help center data: the browse tree and the pages already opened.
 * A docs_updated event (boot.ts) invalidates one module: its pages and the
 * tree are dropped and its revision bumps, so a view showing them refetches.
 */
export const useHelp = defineStore('help', {
  state: () => ({
    tree: null as DocsTree | null,
    pages: {} as Record<string, DocPage>,
    /** Bumped per module on docs_updated. */
    revisions: {} as Record<string, number>,
    /** Bumped on any docs_updated (the tree and search results span modules). */
    revision: 0,
  }),
  actions: {
    async loadTree(force = false): Promise<DocsTree> {
      if (this.tree && !force) return this.tree
      if (!treeInFlight || force) {
        const rev = this.revision
        const p = fetchDocsTree().finally(() => {
          if (treeInFlight === p) treeInFlight = null
        })
        treeInFlight = p
        const tree = await p
        // An update during the fetch makes this answer stale: keep it for the
        // caller but do not cache it.
        if (rev === this.revision) this.tree = tree
        return tree
      }
      return treeInFlight
    },
    async loadPage(module: string, slug: string, force = false): Promise<DocPage> {
      const key = module + '/' + slug
      const hit = this.pages[key]
      if (hit && !force) return hit
      const rev = this.revisions[module] ?? 0
      const page = await fetchDocPage(module, slug)
      if (rev === (this.revisions[module] ?? 0)) this.pages = { ...this.pages, [key]: page }
      return page
    },
    /** Drops what is cached for a module whose documentation changed. */
    invalidate(module: string): void {
      const prefix = module + '/'
      this.pages = Object.fromEntries(Object.entries(this.pages).filter(([k]) => !k.startsWith(prefix)))
      this.tree = null
      treeInFlight = null
      this.revisions = { ...this.revisions, [module]: (this.revisions[module] ?? 0) + 1 }
      this.revision++
    },
  },
})
