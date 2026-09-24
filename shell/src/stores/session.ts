import { defineStore } from 'pinia'
import { api, ApiError, onApiEvent } from '@/api/client'
import type { components } from '@/api/schema'

export type Module = components['schemas']['Module']
export type Abilities = components['schemas']['Abilities']

/** A navigation contribution, normalised. */
export interface NavEntry {
  module: string
  title: string
  path: string
  icon: string
  order: number
}

/** The navigation of one module: a menu with its entries as sub-items. */
export interface NavGroup {
  module: string
  title: string
  icon: string
  order: number
  entries: NavEntry[]
}

/** Shape of GET /gateway/v1/me. */
export interface Me {
  user_id: string
  tenant_id: string
  session_id?: string
  roles?: string[]
  amr?: string[]
  operator?: boolean
  source?: 'session' | 'bearer'
  display_name?: string
  avatar_url?: string
}

/** DOM event a module dispatches after changing the signed-in person's profile. */
export const SESSION_CHANGED_EVENT = 'freya:session-changed'

export type SessionStatus = 'unknown' | 'anonymous' | 'authenticated' | 'outage'

export const useSession = defineStore('session', {
  state: () => ({
    status: 'unknown' as SessionStatus,
    userId: '' as string,
    tenantId: '' as string,
    sessionId: '' as string,
    roles: [] as string[],
    operator: false,
    displayName: '' as string,
    avatarUrl: '' as string,
    modules: [] as Module[],
    pending: null as Promise<void> | null,
  }),
  getters: {
    signedIn: (s) => s.status === 'authenticated',
    hasRole: (s) => (role: string) => s.roles.includes(role),
    hasAnyRole: (s) => (roles: string[]) => roles.some((r) => s.roles.includes(r)),
    /** Up to two initials for the avatar placeholder. */
    initials: (s): string =>
      (s.displayName || s.userId)
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((w) => w[0]!.toUpperCase())
        .join(''),
    /** Navigation entries of every visible module, ordered. */
    nav: (s): NavEntry[] =>
      s.modules
        .flatMap((m) =>
          (m.nav ?? [])
            .filter((n) => !!n.title && !!n.path)
            .map((n) => ({ module: m.module ?? '', title: n.title ?? '', path: n.path ?? '', icon: n.icon ?? '', order: n.order ?? 0 })),
        )
        .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title)),
    /**
     * Navigation grouped by module: one menu per module (titled by its display
     * name, ordered by its first entry) holding that module's entries.
     */
    navGroups(): NavGroup[] {
      const groups = new Map<string, NavGroup>()
      for (const n of this.nav) {
        let g = groups.get(n.module)
        if (!g) {
          const m = this.modules.find((x) => x.module === n.module)
          g = { module: n.module, title: m?.display_name || n.module, icon: n.icon || 'mdi-view-module-outline', order: n.order, entries: [] }
          groups.set(n.module, g)
        }
        g.entries.push(n)
      }
      return [...groups.values()].sort((a, b) => a.order - b.order || a.title.localeCompare(b.title))
    },
  },
  actions: {
    /** Loads the identity once; concurrent callers share the request. */
    load(force = false): Promise<void> {
      if (this.pending && !force) return this.pending
      this.pending = (async () => {
        try {
          this.apply(await api<Me>('GET', '/gateway/v1/me'))
        } catch (err) {
          if (err instanceof ApiError && err.status === 401) this.reset('anonymous')
          else if (err instanceof ApiError && (err.status === 0 || err.status >= 500)) this.status = 'outage'
          else throw err
        } finally {
          this.pending = null
        }
      })()
      return this.pending
    },
    apply(me: Me): void {
      this.userId = me.user_id
      this.tenantId = me.tenant_id
      this.sessionId = me.session_id ?? ''
      this.roles = me.roles ?? []
      this.operator = me.operator ?? false
      this.displayName = me.display_name ?? ''
      this.avatarUrl = me.avatar_url ?? ''
      this.status = 'authenticated'
    },
    /** Re-reads the identity (a module reported a profile change). */
    async refresh(): Promise<void> {
      if (this.status !== 'authenticated') return
      await this.load(true)
    },
    /** Fetches the modules visible to the caller (remote entries and navigation). */
    async loadModules(): Promise<void> {
      this.modules = await api<Module[]>('GET', '/gateway/v1/me/modules')
    },
    /** Ends the platform session (relayed to the auth module) and clears local state. */
    async signOut(): Promise<void> {
      try {
        await api('POST', '/api/v1/signout')
      } catch (err) {
        if (!(err instanceof ApiError)) throw err
      } finally {
        this.reset()
      }
    },
    reset(status: SessionStatus = 'anonymous'): void {
      this.userId = ''
      this.tenantId = ''
      this.sessionId = ''
      this.roles = []
      this.operator = false
      this.displayName = ''
      this.avatarUrl = ''
      this.modules = []
      this.status = status
    },
    /** Keeps the store in step with transport events (session loss, outage). */
    bindEvents(): () => void {
      return onApiEvent((ev) => {
        if (ev === 'unauthenticated' && this.status === 'authenticated') this.reset()
        if (ev === 'outage') this.status = 'outage'
        if (ev === 'recovered' && this.status === 'outage') this.status = 'unknown'
      })
    },
  },
})
