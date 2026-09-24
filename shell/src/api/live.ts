// Shared platform realtime bus. One SSE connection to the gateway
// (GET /gateway/v1/stream) carries events any backend module publishes to the
// shared Valkey stream; remotes subscribe by event type via the BootContext.
// EventSource reconnects on its own and replays from Last-Event-ID, so
// listeners registered here survive reconnects.
export type LiveHandler = (data: unknown) => void

export interface LiveBus {
  /** Subscribe to a namespaced event type (e.g. "certificate.issued"); returns an unsubscribe fn. */
  on(type: string, fn: LiveHandler): () => void
}

const handlers = new Map<string, Set<LiveHandler>>()
const bound = new Set<string>()
let es: EventSource | null = null

function ensure(): void {
  if (es || typeof EventSource === 'undefined') return
  es = new EventSource('/gateway/v1/stream', { withCredentials: true })
  for (const type of handlers.keys()) bindType(type)
}

function bindType(type: string): void {
  if (!es || bound.has(type)) return
  bound.add(type)
  es.addEventListener(type, (ev) => {
    let data: unknown = null
    try {
      data = JSON.parse((ev as MessageEvent<string>).data)
    } catch {
      data = (ev as MessageEvent).data
    }
    handlers.get(type)?.forEach((fn) => {
      try {
        fn(data)
      } catch {
        /* a listener throwing must not break the stream */
      }
    })
  })
}

export const live: LiveBus = {
  on(type, fn) {
    let set = handlers.get(type)
    if (!set) {
      set = new Set()
      handlers.set(type, set)
    }
    set.add(fn)
    ensure()
    bindType(type)
    return () => {
      set!.delete(fn)
    }
  },
}
