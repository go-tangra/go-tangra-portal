import { init, loadRemote, registerRemotes, type ModuleFederation } from '@module-federation/enhanced/runtime'
import { hostConfig } from '../../module-federation.config'
import type { Module } from '@/stores/session'

export interface RemoteRef {
  name: string
  entry: string
}

let instance: ModuleFederation | null = null
const known = new Map<string, string>()

/** Initialises the federation host once (shared singletons from the config). */
export function federationHost(): ModuleFederation {
  if (!instance) instance = init({ name: hostConfig.name, remotes: [], shared: hostConfig.shared as unknown as NonNullable<Parameters<typeof init>[0]['shared']> })
  return instance
}

/**
 * Registers the remotes announced by the gateway. Entries are same-origin
 * manifests under /m/<module>/; a changed entry re-registers with force so a
 * new module version is picked up without a reload.
 */
export function registerModules(modules: Module[]): RemoteRef[] {
  federationHost()
  const refs: RemoteRef[] = []
  const fresh: { name: string; entry: string; alias?: string }[] = []
  for (const m of modules) {
    const entry = m.remote?.entry
    if (!m.module || !entry || !entry.startsWith('/m/' + m.module + '/')) continue
    refs.push({ name: m.module, entry })
    if (known.get(m.module) !== entry) {
      known.set(m.module, entry)
      fresh.push({ name: m.module, entry, alias: m.module })
    }
  }
  if (fresh.length) registerRemotes(fresh, { force: true })
  return refs
}

export class RemoteLoadError extends Error {
  constructor(
    public readonly module: string,
    public readonly expose: string,
    cause: unknown,
  ) {
    super(`remote ${module}${expose} failed to load`)
    this.name = 'RemoteLoadError'
    this.cause = cause
  }
}

/**
 * Loads an exposed module (e.g. "./routes") with bounded retries. Failures are
 * isolated to the module: the caller renders its error boundary and the rest
 * of the shell keeps working.
 */
export async function loadExpose<T = unknown>(module: string, expose = './routes', retries = 2, delayMs = 300): Promise<T> {
  federationHost()
  const id = module + expose.replace(/^\./, '')
  let last: unknown
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const mod = await loadRemote<T>(id)
      if (mod === null || mod === undefined) throw new Error('empty module')
      return mod
    } catch (err) {
      last = err
      if (attempt < retries) await new Promise((r) => setTimeout(r, delayMs * (attempt + 1)))
    }
  }
  throw new RemoteLoadError(module, expose, last)
}

/** Test hook: forget registered entries. */
export function resetFederation(): void {
  known.clear()
  instance = null
}
