// The shell's transport: the kit client (same-origin, CSRF double submit, closed
// reason vocabulary) plus the outage / session-loss events the session store and
// the outage boundary listen to. The same object is handed to remotes as ctx.api.
import { createApi, ApiError, csrfToken, CSRF_COOKIE, CSRF_HEADER, type Api, type Method, type RequestOptions } from '@freya/ui/api'
import type { paths } from './schema'

export { ApiError, csrfToken, CSRF_COOKIE, CSRF_HEADER }
export type { Method, RequestOptions }

// Path names are checked against the OpenAPI contract at compile time.
export type ApiPath = keyof paths

/** Refusal reasons the gateway emits (closed vocabulary). */
export type Reason = 'unauthenticated' | 'forbidden' | 'not_found' | 'validation_failed' | 'temporarily_unavailable' | 'rate_limited' | 'csrf' | 'network' | string

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

/** Maps a refused call onto the shell's events; 5xx becomes temporarily_unavailable. */
function classify(err: unknown): never {
  if (err instanceof ApiError) {
    if (err.status === 0 || err.status >= 500) {
      emit('outage')
      throw err.status >= 500 ? new ApiError(err.status, 'temporarily_unavailable') : err
    }
    emit('recovered')
    if (err.status === 401) emit('unauthenticated')
  }
  throw err
}

// Absolute paths ("/gateway/v1/…", "/api/<module>/…") bypass the base; the base only serves relative module paths.
const transport = createApi({ base: '/gateway/v1' })

/**
 * Calls the gateway (its own API or a module route). Non-2xx responses reject
 * with ApiError carrying the server's `reason`; network failures and 5xx raise
 * the "outage" event so the shell can show its outage boundary.
 */
export const api: Api = (async <T = unknown,>(method: Method, path: ApiPath | string, body?: unknown, opts: RequestOptions = {}): Promise<T> => {
  try {
    const out = await transport<T>(method, path, body, opts)
    emit('recovered')
    return out
  } catch (err) {
    return classify(err)
  }
}) as Api
Object.defineProperty(api, 'base', { value: transport.base })
api.upload = async <T = unknown,>(path: string, file: File, fields?: Record<string, string>): Promise<T> => {
  try {
    const out = await transport.upload<T>(path, file, fields)
    emit('recovered')
    return out
  } catch (err) {
    return classify(err)
  }
}
api.fileUrl = transport.fileUrl
