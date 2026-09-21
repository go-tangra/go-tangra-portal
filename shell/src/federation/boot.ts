import { defineAsyncComponent, defineComponent, h, reactive, type Component } from 'vue'
import type { Router, RouteRecordRaw } from 'vue-router'
import { useSession } from '@/stores/session'
import { ability, clearAbilities, loadAbilities } from '@/casl/ability'
import { api } from '@/api/client'
import { subscribeEvents } from '@/api/events'
import { live, type LiveBus } from '@/api/live'
import { SESSION_CHANGED_EVENT } from '@/stores/session'
import { useRegistry } from '@/stores/registry'
import { loadExpose, registerModules, RemoteLoadError } from '@/federation/runtime'
import RemoteBoundary from '@/components/RemoteBoundary.vue'

/** What a remote's ./routes expose must export (contracts/federation.md). */
export interface RoutesExpose {
  routes?: RouteRecordRaw[]
  default?: RouteRecordRaw[]
}

/** What a remote's optional ./boot expose may export. */
export interface BootExpose {
  default?: (ctx: BootContext) => void | Promise<void>
}

export interface BootContext {
  ability: typeof ability
  session: ReturnType<typeof useSession>
  api: typeof api
  /** Shared realtime bus: subscribe to platform events any module publishes. */
  live: LiveBus
}

/** What a remote's optional ./header expose must export (contracts/shell-changes.md). */
export interface HeaderExpose {
  /** Rendered in the app bar, right of the theme toggle, left of the avatar; receives the boot context as props. */
  default: Component
}

/** Header components of the mounted modules (module → component), rendered by the layout. */
export const headerSlots = reactive(new Map<string, Component>())

/** Modules whose remote failed to load (rendered by the module error boundary). */
export const failedModules = new Set<string>()
const mounted = new Map<string, string[]>() // module → route names

/** Wraps a remote route component in the module's error boundary. */
export function wrapRoute(route: RouteRecordRaw, module: string): RouteRecordRaw {
  const original = route.component as Component | (() => Promise<unknown>) | undefined
  const wrapped = original
    ? defineComponent({
        name: `Remote:${module}`,
        setup() {
          return () => h(RemoteBoundary, { module }, () => h(typeof original === 'function' ? defineAsync(original as () => Promise<unknown>) : original))
        },
      })
    : undefined
  const children = route.children?.map((c) => wrapRoute(c, module))
  return { ...route, ...(wrapped ? { component: wrapped } : {}), ...(children ? { children } : {}), meta: { ...(route.meta ?? {}), module } } as RouteRecordRaw
}

const asyncCache = new Map<() => Promise<unknown>, Component>()
// Lazy route components resolve outside <Suspense>: use defineAsyncComponent.
function defineAsync(loader: () => Promise<unknown>): Component {
  let c = asyncCache.get(loader)
  if (!c) {
    c = defineAsyncComponent(async () => {
      const mod = (await loader()) as { default?: Component }
      return mod.default ?? (mod as Component)
    })
    asyncCache.set(loader, c)
  }
  return c
}

/** Loads a module's routes and mounts them under its error boundary. */
export async function mountModule(router: Router, module: string): Promise<void> {
  const exposed = await loadExpose<RoutesExpose>(module, './routes')
  const routes = exposed.routes ?? exposed.default ?? []
  const names: string[] = []
  routes.forEach((r, i) => {
    const name = r.name ?? `remote:${module}:${i}`
    router.addRoute(wrapRoute({ ...r, name }, module))
    names.push(String(name))
  })
  mounted.set(module, names)
  failedModules.delete(module)
  try {
    const boot = await loadExpose<BootExpose>(module, './boot', 0)
    await boot.default?.({ ability, session: useSession(), api, live })
  } catch (err) {
    if (!(err instanceof RemoteLoadError)) throw err // ./boot is optional
  }
  try {
    const header = await loadExpose<HeaderExpose>(module, './header', 0)
    if (header.default) headerSlots.set(module, header.default)
  } catch (err) {
    if (!(err instanceof RemoteLoadError)) throw err // ./header is optional
  }
}

/** Unmounts a withdrawn module's routes. */
export function unmountModule(router: Router, module: string): void {
  for (const name of mounted.get(module) ?? []) if (router.hasRoute(name)) router.removeRoute(name)
  mounted.delete(module)
  headerSlots.delete(module)
}

/** Registers and mounts every visible module; failures stay isolated. */
export async function composeModules(router: Router): Promise<void> {
  const session = useSession()
  const refs = registerModules(session.modules)
  const known = new Set(refs.map((r) => r.name))
  for (const module of [...mounted.keys()]) if (!known.has(module)) unmountModule(router, module)
  await Promise.all(
    refs.filter((ref) => !mounted.has(ref.name)).map(async (ref) => {
      try {
        await mountModule(router, ref.name)
      } catch (err) {
        console.error(`[shell] module ${ref.name} unavailable`, err)
        failedModules.add(ref.name)
      }
    }),
  )
}

/**
 * Boot sequence: identity → modules + abilities → remotes → live updates.
 * A failing remote never breaks the shell or the other modules.
 */
export async function boot(router: Router): Promise<() => void> {
  const session = useSession()
  await session.load()
  if (!session.signedIn) return () => undefined
  try {
    await Promise.all([session.loadModules(), loadAbilities()])
  } catch {
    return () => undefined
  }
  await composeModules(router)
  if (mounted.size) await router.replace(router.currentRoute.value.fullPath)
  const registry = useRegistry()
  const stop = subscribeEvents({
    onOpen: () => registry.setGateway(false),
    onError: () => registry.setGateway(true),
    onRegistry: async (e) => {
      registry.apply(e.kind, e.module)
      if (e.kind === 'unhealthy' || e.kind === 'recovered') return
      try {
        await Promise.all([session.loadModules(), loadAbilities()])
        await composeModules(router)
      } catch {
        /* the next event or reload recovers */
      }
    },
    onAbilities: async () => {
      try {
        await loadAbilities()
      } catch {
        /* keep the last known abilities */
      }
    },
  })
  // A module (the auth remote) reports a profile change: the gateway already
  // dropped its cached identity, so /me answers with the new attributes.
  const onChanged = (): void => void session.refresh()
  window.addEventListener(SESSION_CHANGED_EVENT, onChanged)
  const unbind = session.$subscribe((_m, state) => {
    if (state.status !== 'authenticated') {
      clearAbilities()
      for (const module of [...mounted.keys()]) unmountModule(router, module)
    }
  })
  return () => {
    stop()
    unbind()
    window.removeEventListener(SESSION_CHANGED_EVENT, onChanged)
  }
}
