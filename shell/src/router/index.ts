import { createRouter, createWebHistory, type RouteRecordRaw, type Router } from 'vue-router'
import { useSession } from '@/stores/session'

declare module 'vue-router' {
  interface RouteMeta {
    /** No session required. */
    public?: boolean
    /** Platform operator only. */
    operator?: boolean
    /** Owning module (federated routes). */
    module?: string
    layout?: 'default' | 'bare'
  }
}

// Shell-owned routes; module routes are added at runtime by the federation
// boot (see main.ts) under their own error boundary.
export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'home', component: () => import('@/views/Home.vue') },
  { path: '/ops', name: 'ops', component: () => import('@/views/ops/Registrations.vue'), meta: { operator: true } },
  { path: '/ops/allowlist', name: 'ops-allowlist', component: () => import('@/views/ops/Allowlist.vue'), meta: { operator: true } },
  { path: '/ops/audit', name: 'ops-audit', component: () => import('@/views/ops/Audit.vue'), meta: { operator: true } },
  { path: '/outage', name: 'outage', component: () => import('@/views/Outage.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/forbidden', name: 'forbidden', component: () => import('@/views/Forbidden.vue') },
  // Not public: module routes only exist for a signed-in browser, so an unknown
  // path from an anonymous one goes to sign-in (and comes back to the module).
  { path: '/:pathMatch(.*)*', name: 'notfound', component: () => import('@/views/NotFound.vue') },
]

/** Where an anonymous browser is sent: the auth module's sign-in page, served through the gateway. */
export const SIGNIN_PATH = '/console/signin'

/** Full-page navigation (replaceable in tests; jsdom's location is immutable). */
export const navigation = { assign: (url: string): void => window.location.assign(url) }

export function createShellRouter(): Router {
  const router = createRouter({ history: createWebHistory('/'), routes })
  router.beforeEach(async (to) => {
    const session = useSession()
    if (session.status === 'unknown') await session.load()
    if (session.status === 'outage' && to.name !== 'outage') return { name: 'outage' }
    if (to.meta.public) return true
    if (!session.signedIn) {
      // The sign-in page belongs to the auth module. If we are already heading
      // there — e.g. the gateway served the shell for /console/signin because
      // auth is unreachable, so the catch-all route matched it — never wrap it
      // in another `next` or reload it into itself: that produces the endless
      // /console/signin?next=%2Fconsole%2Fsignin%3Fnext%3D… loop.
      if (to.fullPath === SIGNIN_PATH || to.fullPath.startsWith(SIGNIN_PATH + '?')) return true
      navigation.assign(SIGNIN_PATH + '?next=' + encodeURIComponent(to.fullPath))
      return false
    }
    if (to.meta.operator && !session.operator) return { name: 'forbidden' }
    return true
  })
  return router
}

export const router = createShellRouter()
