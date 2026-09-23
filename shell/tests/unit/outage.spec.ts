import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { h, nextTick } from 'vue'
import ModuleBoundary from '@/components/ModuleBoundary.vue'
import { useRegistry } from '@/stores/registry'

describe('module outage handling', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('shows an outage card for unhealthy modules and clears it on recovery', async () => {
    const registry = useRegistry()
    const w = mount(ModuleBoundary, { props: { module: 'hello' }, slots: { default: () => h('p', { 'data-test': 'content' }, 'hi') } })
    expect(w.find('[data-test="content"]').exists()).toBe(true)
    registry.apply('unhealthy', 'hello')
    await nextTick()
    expect(w.find('[data-test="module-outage"]').exists()).toBe(true)
    expect(w.find('[data-test="content"]').exists()).toBe(false)
    registry.apply('recovered', 'hello')
    await nextTick()
    expect(w.find('[data-test="content"]').exists()).toBe(true)
    registry.apply('withdrawn', 'hello')
    await nextTick()
    expect(w.find('[data-test="module-outage"]').exists()).toBe(true)
    // Other modules are unaffected.
    expect(registry.unavailable('auth')).toBe(false)
    registry.apply('exploded', 'hello')
    expect(registry.stateOf('hello')).toBe('withdrawn')
    registry.setGateway(true)
    expect(registry.gatewayDown).toBe(true)
  })
})
