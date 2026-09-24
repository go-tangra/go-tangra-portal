import { createMongoAbility, type MongoAbility, type RawRuleOf } from '@casl/ability'
import { unpackRules, type PackRule } from '@casl/ability/extra'
import { abilitiesPlugin } from '@casl/vue'
import type { App } from 'vue'
import { api } from '@/api/client'
import type { Abilities } from '@/stores/session'

export type AppAbility = MongoAbility
type RawRule = RawRuleOf<AppAbility>

/** One shared ability instance; remotes receive it through @casl/vue. */
export const ability: AppAbility = createMongoAbility([])

/** Version of the last applied abilities document (SSE refetch trigger). */
export let abilitiesVersion = ''

/**
 * Applies a /gateway/v1/me/abilities document. Rules are packed per module
 * (CASL packRules); subjects are namespaced by the manifest, so modules cannot
 * collide. Rules whose API permission the caller lacks are never present.
 */
export function applyAbilities(doc: Abilities): void {
  const rules: RawRule[] = []
  for (const packed of Object.values(doc.modules ?? {})) {
    rules.push(...unpackRules<RawRule>(packed as PackRule<RawRule>[]))
  }
  ability.update(rules)
  abilitiesVersion = doc.version ?? ''
}

/** Fetches and applies the caller's abilities. */
export async function loadAbilities(): Promise<void> {
  applyAbilities(await api<Abilities>('GET', '/gateway/v1/me/abilities'))
}

/** Clears every rule (sign-out, session loss). */
export function clearAbilities(): void {
  ability.update([])
  abilitiesVersion = ''
}

/** Installs the CASL plugin so `$ability`, `$can` and useAbility() work in remotes. */
export function installAbilities(app: App): void {
  app.use(abilitiesPlugin, ability, { useGlobalProperties: true })
}
