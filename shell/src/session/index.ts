// The shell's session keeper (one per page) and the expiry watcher.
import { createKeeper, refreshSession } from '@/session/keeper'
import { checkSession, toSignin, watchSessionExpiry } from '@/session/expiry'
import { useSession } from '@/stores/session'

function storage(): Storage | undefined {
  try {
    return window.localStorage
  } catch {
    return undefined
  }
}

/** Renews the session while the person is active; ends it when they leave it unattended. */
export const keeper = createKeeper({
  now: () => Date.now(),
  refresh: refreshSession,
  // The idle deadline passed: end the session everywhere, then sign in again.
  expire: () => {
    void useSession()
      .signOut()
      .catch(() => undefined)
      .finally(toSignin)
  },
  storage: storage(),
  target: window,
  doc: document,
})

export { checkSession, toSignin, watchSessionExpiry }
