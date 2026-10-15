export interface RegistryEvent {
  kind: string
  module: string
  version: number
}

export interface EventHandlers {
  onRegistry?: (e: RegistryEvent) => void
  onAbilities?: (version: string) => void
  /** A module's help pages changed (re-indexed or removed). */
  onDocs?: (module: string) => void
  onOpen?: () => void
  onError?: () => void
}

/**
 * Subscribes to the gateway's server-sent events (registry changes, ability
 * version changes, module documentation changes). EventSource reconnects on its own; the returned function
 * closes the stream.
 */
export function subscribeEvents(h: EventHandlers, url = '/gateway/v1/events'): () => void {
  if (typeof EventSource === 'undefined') return () => undefined
  const es = new EventSource(url, { withCredentials: true })
  es.addEventListener('registry', (ev) => {
    try {
      h.onRegistry?.(JSON.parse((ev as MessageEvent<string>).data) as RegistryEvent)
    } catch {
      /* malformed event: ignore */
    }
  })
  es.addEventListener('abilities', (ev) => {
    try {
      h.onAbilities?.((JSON.parse((ev as MessageEvent<string>).data) as { version: string }).version)
    } catch {
      /* ignore */
    }
  })
  es.addEventListener('docs_updated', (ev) => {
    try {
      const { module } = JSON.parse((ev as MessageEvent<string>).data) as { module: unknown }
      if (typeof module === 'string' && module) h.onDocs?.(module)
    } catch {
      /* ignore */
    }
  })
  es.onopen = () => h.onOpen?.()
  es.onerror = () => h.onError?.()
  return () => es.close()
}
