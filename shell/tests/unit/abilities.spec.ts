import { beforeEach, describe, expect, it, vi } from 'vitest'
import { packRules } from '@casl/ability/extra'
import { ability, applyAbilities } from '@/casl/ability'
import { subscribeEvents } from '@/api/events'

class FakeEventSource {
  static instances: FakeEventSource[] = []
  listeners: Record<string, (ev: MessageEvent<string>) => void> = {}
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  closed = false
  constructor(public url: string) {
    FakeEventSource.instances.push(this)
  }
  addEventListener(name: string, fn: (ev: MessageEvent<string>) => void): void {
    this.listeners[name] = fn
  }
  emit(name: string, data: string): void {
    this.listeners[name]?.(new MessageEvent(name, { data }))
  }
  close(): void {
    this.closed = true
  }
}

describe('live ability updates', () => {
  beforeEach(() => {
    FakeEventSource.instances = []
    vi.stubGlobal('EventSource', FakeEventSource)
  })

  it('refetches abilities on SSE events and updates the shared ability', async () => {
    applyAbilities({ version: 'v1', modules: { hello: packRules([{ action: 'read', subject: 'Greeting' }]) } })
    expect(ability.can('create', 'Greeting')).toBe(false)
    let fetched = 0
    const stop = subscribeEvents({
      onAbilities: () => {
        fetched++
        applyAbilities({ version: 'v2', modules: { hello: packRules([{ action: 'create', subject: 'Greeting' }]) } })
      },
    })
    const es = FakeEventSource.instances[0]!
    expect(es.url).toBe('/gateway/v1/events')
    es.emit('abilities', JSON.stringify({ version: 'v2' }))
    es.emit('abilities', 'not json')
    expect(fetched).toBe(1)
    expect(ability.can('create', 'Greeting')).toBe(true)
    let registry: unknown = null
    const stop2 = subscribeEvents({ onRegistry: (e) => (registry = e) })
    FakeEventSource.instances[1]!.emit('registry', JSON.stringify({ kind: 'withdrawn', module: 'hello', version: 9 }))
    expect(registry).toEqual({ kind: 'withdrawn', module: 'hello', version: 9 })
    stop()
    stop2()
    expect(es.closed).toBe(true)
  })

  it('is a no-op without EventSource support', () => {
    vi.stubGlobal('EventSource', undefined)
    expect(subscribeEvents({})).toBeTypeOf('function')
  })
})
