// Sends the person to the sign-in page as soon as their session has ended,
// instead of leaving the page showing "Your session has ended" errors.
//
// A 401 from any client — the shell's own, or a module remote's (they share
// the kit's API module, a federation singleton) — or a live stream dropping
// triggers a check of /gateway/v1/me; only a confirmed loss redirects, so a
// module refusing one call for its own reasons never signs anyone out.
import { onUnauthenticated } from '@go-tangra/ui/api'
import { onApiEvent } from '@/api/client'
import { useSession } from '@/stores/session'
import { navigation, SIGNIN_PATH } from '@/router'

let checking: Promise<void> | null = null
let leaving = false

/** Where to come back to after signing in (the current page). */
export function signinUrl(): string {
  const here = window.location.pathname + window.location.search + window.location.hash
  return SIGNIN_PATH + '?next=' + encodeURIComponent(here)
}

/** Leaves for the sign-in page once (never wrapping the sign-in page in itself). */
export function toSignin(): void {
  if (leaving) return
  const path = window.location.pathname
  if (path === SIGNIN_PATH || path.startsWith(SIGNIN_PATH + '/')) return
  leaving = true
  navigation.assign(signinUrl())
}

/**
 * Confirms whether a signed-in session ended and, if so, leaves for sign-in.
 * Calls made while the browser is anonymous (sign-in pages) are ignored.
 */
export function checkSession(): Promise<void> {
  const session = useSession()
  if (session.status !== 'authenticated') return Promise.resolve()
  if (checking) return checking
  checking = (async () => {
    try {
      await session.load(true)
      if (session.status === 'anonymous') toSignin()
    } catch {
      /* not a session answer (outage): the outage boundary handles it */
    } finally {
      checking = null
    }
  })()
  return checking
}

/** Watches for session loss; returns the unsubscribe function. */
export function watchSessionExpiry(): () => void {
  const offKit = onUnauthenticated(() => void checkSession())
  const offShell = onApiEvent((ev) => {
    if (ev === 'unauthenticated') void checkSession()
  })
  return () => {
    offKit()
    offShell()
  }
}

/** Test hook: forget a redirect already made. */
export function resetExpiryForTests(): void {
  leaving = false
  checking = null
}
