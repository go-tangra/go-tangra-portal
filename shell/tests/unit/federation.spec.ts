import { beforeEach, describe, expect, it, vi } from 'vitest'

const { registerRemotes, loadRemote } = vi.hoisted(() => ({ registerRemotes: vi.fn(), loadRemote: vi.fn() }))
vi.mock('@module-federation/enhanced/runtime', () => ({
  init: vi.fn(() => ({})),
  registerRemotes,
  loadRemote,
}))

import { loadExpose, registerModules, RemoteLoadError, resetFederation } from '@/federation/runtime'

describe('federation runtime wrapper', () => {
  beforeEach(() => {
    resetFederation()
    registerRemotes.mockClear()
    loadRemote.mockReset()
  })

  it('registers only same-origin entries under /m/<module>/ and re-registers changed versions', () => {
    const refs = registerModules([
      { module: 'orders', remote: { entry: '/m/orders/mf-manifest.json' } },
      { module: 'evil', remote: { entry: 'https://evil.example/mf-manifest.json' } },
      { module: 'billing', remote: { entry: '/m/other/mf-manifest.json' } },
    ])
    expect(refs.map((r) => r.name)).toEqual(['orders'])
    expect(registerRemotes).toHaveBeenCalledTimes(1)
    registerModules([{ module: 'orders', remote: { entry: '/m/orders/mf-manifest.json' } }])
    expect(registerRemotes).toHaveBeenCalledTimes(1)
    registerModules([{ module: 'orders', remote: { entry: '/m/orders/mf-manifest.json?v=2' } }])
    expect(registerRemotes).toHaveBeenCalledTimes(2)
    expect(registerRemotes.mock.calls[1]?.[1]).toEqual({ force: true })
  })

  it('retries a failing remote and isolates the failure', async () => {
    loadRemote.mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce({ routes: [] })
    expect(await loadExpose('orders', './routes', 2, 1)).toEqual({ routes: [] })
    expect(loadRemote).toHaveBeenCalledWith('orders/routes')
    loadRemote.mockReset()
    loadRemote.mockRejectedValue(new Error('down'))
    await expect(loadExpose('orders', './nav', 1, 1)).rejects.toBeInstanceOf(RemoteLoadError)
    expect(loadRemote).toHaveBeenCalledTimes(2)
  })
})
