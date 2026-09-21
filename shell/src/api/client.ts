import type { paths } from './schema'

// Path names are checked against the OpenAPI contract at compile time.
export type ApiPath = keyof paths
export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE'

export const CSRF_COOKIE = '__Host-csrf'
export const CSRF_HEADER = 'X-CSRF-Token'

/** Refusal reasons the gateway emits (closed vocabulary). */
export type Reason = 'unauthenticated' | 'forbidden' | 'not_found' | 'validation_failed' | 'temporarily_unavailable' | 'rate_limited' | 'csrf' | 'network' | string

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly reason: Reason,
  ) {
    super(reason)
    this.name = 'ApiError'
  }
}

export type ApiEvent = 'outage' | 'unauthenticated' | 'recovered'
type Listener = (event: ApiEvent) => void
const listeners = new Set<Listener>()

/** Subscribe to transport-level events (outage, session loss). */
export function onApiEvent(listener: Listener): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function emit(event: ApiEvent): void {
  for (const l of listeners) l(event)
}

/** Reads the double-submit CSRF cookie issued by the gateway edge. */
export function csrfToken(): string {
  const prefix = CSRF_COOKIE + '='
  const hit = document.cookie.split('; ').find((c) => c.startsWith(prefix))
  return hit ? decodeURIComponent(hit.slice(prefix.length)) : ''
}

export interface RequestOptions {
  signal?: AbortSignal
  query?: Record<string, string | number | undefined>
}

/**
 * Calls the gateway (its own API or a module route). Non-2xx responses reject
 * with ApiError carrying the server's `reason`; network failures and 5xx raise
 * the "outage" event so the shell can show its outage boundary.
 */
export async function api<T = unknown>(method: Method, path: ApiPath | string, body?: unknown, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers[CSRF_HEADER] = csrfToken()
  let url: string = path
  if (opts.query) {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(opts.query)) if (v !== undefined) q.set(k, String(v))
    const s = q.toString()
    if (s) url += (url.includes('?') ? '&' : '?') + s
  }
  let res: Response
  try {
    res = await fetch(url, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? null : JSON.stringify(body),
      ...(opts.signal ? { signal: opts.signal } : {}),
    })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    emit('outage')
    throw new ApiError(0, 'network')
  }
  if (res.status >= 500) {
    emit('outage')
    throw new ApiError(res.status, 'temporarily_unavailable')
  }
  emit('recovered')
  if (res.status === 204) return undefined as T
  const data: unknown = await res.json().catch(() => ({}))
  if (!res.ok) {
    const reason = typeof data === 'object' && data !== null && 'reason' in data ? String((data as { reason: unknown }).reason) : 'error'
    if (res.status === 401) emit('unauthenticated')
    throw new ApiError(res.status, reason)
  }
  return data as T
}
