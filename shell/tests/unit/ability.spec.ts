import { describe, expect, it } from 'vitest'
import { packRules } from '@casl/ability/extra'
import { ability, abilitiesVersion, applyAbilities, clearAbilities } from '@/casl/ability'

describe('casl provider', () => {
  it('unpacks per-module packed rules into one ability', () => {
    applyAbilities({
      tenant: 't1',
      user: 'u1',
      roles: ['admin'],
      version: 'v7',
      modules: {
        orders: packRules([{ action: 'read', subject: 'Order' }, { action: 'update', subject: 'Order', conditions: { ownerId: 'u1' } }]),
        billing: packRules([{ action: 'read', subject: 'Invoice', inverted: true, reason: 'not yet' }]),
      },
    })
    expect(ability.can('read', 'Order')).toBe(true)
    expect(ability.can('update', { __caslSubjectType__: 'Order', ownerId: 'u1' } as never)).toBe(true)
    expect(ability.can('update', { __caslSubjectType__: 'Order', ownerId: 'x' } as never)).toBe(false)
    expect(ability.can('read', 'Invoice')).toBe(false)
    expect(ability.can('delete', 'Order')).toBe(false)
    expect(abilitiesVersion).toBe('v7')
    clearAbilities()
    expect(ability.can('read', 'Order')).toBe(false)
  })
})
