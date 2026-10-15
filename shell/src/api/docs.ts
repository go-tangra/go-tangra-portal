// Help center API: module documentation search, the browse tree and pages
// (GET /gateway/v1/docs/…). Types come from the generated OpenAPI schema.
import { api } from './client'
import type { components, operations } from './schema'

export type DocsSearchPage = components['schemas']['DocsSearchPage']
export type DocsSearchHit = DocsSearchPage['items'][number]
export type DocsTree = components['schemas']['DocsTree']
export type DocsTreeModule = DocsTree['modules'][number]
export type DocPage = components['schemas']['DocPage']
export type DocKind = DocPage['kind']
export type DocsSearchQuery = operations['searchDocs']['parameters']['query']

export const DOC_KINDS: readonly DocKind[] = ['guide', 'example', 'reference', 'faq']
const KIND_LABELS: Record<DocKind, { one: string; many: string; color: 'info' | 'success' | 'neutral' | 'warning' }> = {
  guide: { one: 'Guide', many: 'Guides', color: 'info' },
  example: { one: 'Example', many: 'Examples', color: 'success' },
  reference: { one: 'Reference', many: 'Reference', color: 'neutral' },
  faq: { one: 'FAQ', many: 'FAQ', color: 'warning' },
}
export const isKind = (k: unknown): k is DocKind => typeof k === 'string' && (DOC_KINDS as readonly string[]).includes(k)
export const kindLabel = (k: string, many = false): string => (isKind(k) ? KIND_LABELS[k][many ? 'many' : 'one'] : k)
export const kindColor = (k: string): 'info' | 'success' | 'neutral' | 'warning' => (isKind(k) ? KIND_LABELS[k].color : 'neutral')

/** Console route of a help page (slug segments encoded, slashes kept). */
export function helpPath(module: string, slug: string, hash = ''): string {
  return '/help/' + encodeURIComponent(module) + '/' + slug.split('/').map(encodeURIComponent).join('/') + hash
}

/**
 * The search snippet is HTML the gateway already escaped, with matches in
 * <mark>. Defence in depth before v-html: keep <mark>/</mark> and turn any
 * other angle bracket into text, so nothing but highlights can render.
 */
export function safeSnippet(snippet: string): string {
  return snippet
    .split(/(<\/?mark>)/)
    .map((part) => (part === '<mark>' || part === '</mark>' ? part : part.replace(/</g, '&lt;').replace(/>/g, '&gt;')))
    .join('')
}

export function searchDocs(query: DocsSearchQuery, signal?: AbortSignal): Promise<DocsSearchPage> {
  return api<DocsSearchPage>('GET', '/gateway/v1/docs/search', undefined, { query: { ...query }, ...(signal ? { signal } : {}) })
}

export function fetchDocsTree(): Promise<DocsTree> {
  return api<DocsTree>('GET', '/gateway/v1/docs/tree')
}

export function fetchDocPage(module: string, slug: string): Promise<DocPage> {
  return api<DocPage>('GET', '/gateway/v1/docs/' + encodeURIComponent(module) + '/' + slug.split('/').map(encodeURIComponent).join('/'))
}
