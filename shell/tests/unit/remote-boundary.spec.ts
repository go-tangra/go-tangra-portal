import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { defineComponent, h, nextTick, ref } from 'vue'
import ModuleBoundary from '@/components/ModuleBoundary.vue'

// A remote built against another @go-tangra/ui version fails inside its own
// boundary with a version-specific message and a retry; a throwing remote is
// isolated from its siblings (FR-011).
describe('remote boundary (kit)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('shows the version-mismatch state with retry for a strictVersion failure', async () => {
    const Mismatch = defineComponent({ setup() { throw new Error('Unsatisfied version 3.9.0 from asset of shared singleton module @go-tangra/ui (required ^4.0.0)') } })
    const w = mount(ModuleBoundary, { props: { module: 'asset' }, slots: { default: () => h(Mismatch) }, global: { config: { errorHandler: () => undefined } } })
    await nextTick()
    const card = w.find('[data-test="module-error"]')
    expect(card.exists()).toBe(true)
    expect(card.attributes('role')).toBe('alert')
    expect(card.text()).toContain('built for a different platform version')
    expect(card.find('button').text()).toContain('Retry')
  })

  it('retries by remounting the remote, and a throwing remote leaves its siblings intact', async () => {
    let attempts = 0
    const Flaky = defineComponent({ setup() { attempts++; if (attempts === 1) throw new Error('boom'); return () => h('p', { 'data-test': 'ok' }, 'loaded') } })
    const Host = defineComponent({
      setup() {
        const shown = ref(true)
        return () => h('div', [
          h('p', { 'data-test': 'sibling' }, 'sibling'),
          shown.value ? h(ModuleBoundary, { module: 'flaky' }, () => h(Flaky)) : null,
          h(ModuleBoundary, { module: 'good' }, () => h('p', { 'data-test': 'good' }, 'good')),
        ])
      },
    })
    const w = mount(Host, { global: { config: { errorHandler: () => undefined } } })
    await nextTick()
    expect(w.find('[data-test="sibling"]').exists()).toBe(true)
    expect(w.find('[data-test="good"]').exists()).toBe(true)
    expect(w.find('[data-test="module-error"]').exists()).toBe(true)
    expect(w.find('[data-test="ok"]').exists()).toBe(false)
    await w.find('[data-test="module-error"] button').trigger('click')
    await nextTick()
    expect(w.find('[data-test="module-error"]').exists()).toBe(false)
    expect(w.find('[data-test="ok"]').exists()).toBe(true)
    expect(attempts).toBe(2)
  })
})
