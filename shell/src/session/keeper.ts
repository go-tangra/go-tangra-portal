// Keeps a signed-in person signed in while they use the platform, and ends
// the session of an unattended one.
//
// - Renewal: while the person is active (input, scrolling, the tab becoming
//   visible) the session is refreshed at most every REFRESH_EVERY through the
//   auth module (POST /api/v1/session/refresh: a new cookie and the absolute
//   expiry moved forward). The idle timeout counts from the last refresh.
// - Warning: WARN_BEFORE the idle deadline a dialog offers to stay signed in.
// - Expiry: at the deadline the session is ended (sign-out) and the browser is
//   sent to the sign-in page, back to the same page afterwards.
//
// Tabs share the deadlines through localStorage, so activity in one tab keeps
// the others from ending the session. An open tab's live streams keep the
// server-side session touched, which is why the idle limit is enforced here.
import { reactive } from 'vue'
import { api, ApiError } from '@/api/client'

export const REFRESH_EVERY = 5 * 60_000
export const WARN_BEFORE = 2 * 60_000
export const TICK = 1_000
/** localStorage key holding the session deadlines shared by the tabs. */
export const STORAGE_KEY = 'freya.session'
const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const

/** POST /api/v1/session/refresh (auth module). */
export interface Refresh {
  session_id: string
  expires_at: string
  idle_timeout_seconds: number
  renewed: boolean
}

/** Deadlines in epoch milliseconds; `at` is when they were set (the newest wins across tabs). */
interface Deadlines {
  idle: number
  expires: number
  at: number
}

/** The part of window/document the keeper listens on. */
export interface Listenable {
  addEventListener(type: string, fn: () => void, opts?: AddEventListenerOptions): void
  removeEventListener(type: string, fn: () => void): void
}

export interface KeeperDeps {
  now: () => number
  refresh: () => Promise<Refresh>
  /** Ends the session (best effort) and leaves for the sign-in page. */
  expire: () => void
  storage?: Pick<Storage, 'getItem' | 'setItem'> | undefined
  /** Where activity is observed (window). */
  target?: Listenable | undefined
  /** The document (tab visibility). */
  doc?: (Listenable & { readonly visibilityState: DocumentVisibilityState }) | undefined
  setInterval?: (fn: () => void, ms: number) => unknown
  clearInterval?: (id: unknown) => void
}

export interface Keeper {
  /** Reactive: a warning is up, and the whole seconds left before the session ends. */
  readonly state: { warning: boolean; secondsLeft: number; running: boolean }
  start(): void
  stop(): void
  /** "Stay signed in": refresh now and drop the warning. */
  stay(): Promise<void>
  /** Runs one tick (tests). */
  tick(): void
}

export function createKeeper(deps: KeeperDeps): Keeper {
  const state = reactive({ warning: false, secondsLeft: 0, running: false })
  const setI = deps.setInterval ?? ((fn: () => void, ms: number) => setInterval(fn, ms))
  const clearI = deps.clearInterval ?? ((id: unknown) => clearInterval(id as ReturnType<typeof setInterval>))
  let timer: unknown = null
  let lastActivity = 0
  let lastRefresh = 0
  let refreshing: Promise<void> | null = null
  let local: Deadlines | null = null
  let expired = false

  function read(): Deadlines | null {
    let shared: Deadlines | null = null
    try {
      const raw = deps.storage?.getItem(STORAGE_KEY)
      if (raw) {
        const d = JSON.parse(raw) as Partial<Deadlines>
        if (typeof d.idle === 'number' && typeof d.expires === 'number' && typeof d.at === 'number') shared = d as Deadlines
      }
    } catch {
      /* storage unavailable or corrupt: this tab's own deadlines apply */
    }
    if (!shared) return local
    if (!local) return shared
    return shared.at >= local.at ? shared : local
  }
  function write(d: Deadlines): void {
    local = d
    try {
      deps.storage?.setItem(STORAGE_KEY, JSON.stringify(d))
    } catch {
      /* private mode: this tab only */
    }
  }

  function refresh(): Promise<void> {
    if (refreshing) return refreshing
    refreshing = (async () => {
      try {
        const r = await deps.refresh()
        const now = deps.now()
        lastRefresh = now
        const expires = Date.parse(r.expires_at)
        write({ idle: now + r.idle_timeout_seconds * 1000, expires: Number.isNaN(expires) ? now + r.idle_timeout_seconds * 1000 : expires, at: now })
        state.warning = false
      } catch (err) {
        // A 401 is handled by the expiry watcher (it confirms and redirects);
        // anything else (outage, network) is retried on the next activity.
        if (!(err instanceof ApiError)) throw err
      } finally {
        refreshing = null
      }
    })()
    return refreshing
  }

  function onActivity(): void {
    lastActivity = deps.now()
    // Acting while the warning is up counts as staying signed in.
    if (state.warning) void refresh()
  }
  function onVisibility(): void {
    if (deps.doc?.visibilityState === 'visible') onActivity()
  }

  function tick(): void {
    if (!state.running || expired) return
    const now = deps.now()
    if (lastActivity > lastRefresh && now - lastRefresh >= REFRESH_EVERY) void refresh()
    const d = read()
    if (!d) return
    // Another tab refreshed: adopt its time so this one does not refresh again at once.
    if (d.at > lastRefresh) lastRefresh = d.at
    const deadline = Math.min(d.idle, d.expires)
    const left = deadline - now
    if (left <= 0) {
      expired = true
      state.warning = false
      stop()
      deps.expire()
      return
    }
    state.warning = left <= WARN_BEFORE
    state.secondsLeft = Math.ceil(left / 1000)
  }

  function start(): void {
    if (state.running) return
    state.running = true
    expired = false
    lastActivity = deps.now()
    for (const ev of ACTIVITY_EVENTS) deps.target?.addEventListener(ev, onActivity, { passive: true })
    deps.doc?.addEventListener('visibilitychange', onVisibility)
    timer = setI(tick, TICK)
    // Signing in or opening a tab is activity: renew right away.
    void refresh()
  }
  function stop(): void {
    if (!state.running) return
    state.running = false
    state.warning = false
    for (const ev of ACTIVITY_EVENTS) deps.target?.removeEventListener(ev, onActivity)
    deps.doc?.removeEventListener('visibilitychange', onVisibility)
    if (timer !== null) clearI(timer)
    timer = null
  }

  return {
    state,
    start,
    stop,
    stay: async () => {
      lastActivity = deps.now()
      await refresh()
    },
    tick,
  }
}

/** Calls the auth module's session refresh through the gateway. */
export function refreshSession(): Promise<Refresh> {
  return api<Refresh>('POST', '/api/v1/session/refresh')
}
