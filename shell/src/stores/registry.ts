import { defineStore } from 'pinia'

export type ModuleState = 'active' | 'draining' | 'unhealthy' | 'revoked' | 'withdrawn'

/**
 * Live view of module states fed by the gateway's SSE feed; the remote
 * boundary shows an outage card for unhealthy or withdrawn modules without a
 * reload and clears it on recovery.
 */
export const useRegistry = defineStore('registry', {
  state: () => ({ states: {} as Record<string, ModuleState>, gatewayDown: false }),
  getters: {
    stateOf: (s) => (module: string): ModuleState => s.states[module] ?? 'active',
    unavailable: (s) => (module: string): boolean => {
      const st = s.states[module]
      return st === 'unhealthy' || st === 'withdrawn' || st === 'revoked' || st === 'draining'
    },
  },
  actions: {
    /** Applies a registry SSE event kind for a module. */
    apply(kind: string, module: string): void {
      const map: Record<string, ModuleState> = { registered: 'active', updated: 'active', recovered: 'active', unhealthy: 'unhealthy', drained: 'draining', revoked: 'revoked', withdrawn: 'withdrawn' }
      const next = map[kind]
      if (next) this.states = { ...this.states, [module]: next }
    },
    setGateway(down: boolean): void {
      this.gatewayDown = down
    },
  },
})
