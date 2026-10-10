// Tailwind only emits CSS for icons the kit lists in ICONS (its safelist): an
// icon the shell names that is not listed renders as nothing. Every icon name
// in the shell's source must therefore be in the kit's list.
import { describe, expect, it } from 'vitest'
import { ICONS } from '@go-tangra/ui'

const sources = import.meta.glob<string>(['../../src/**/*.vue', '../../src/**/*.ts', '!../../src/**/*.d.ts'], { query: '?raw', import: 'default', eager: true })

describe('icons', () => {
  it('every icon the shell names is in the kit list (otherwise it renders blank)', () => {
    const listed = new Set<string>(ICONS)
    const missing: string[] = []
    expect(Object.keys(sources).length).toBeGreaterThan(10)
    for (const [file, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/['"](mdi-[a-z0-9-]+)['"]/g)) {
        if (!listed.has(m[1]!)) missing.push(m[1] + ' in ' + file.replace('../../src/', ''))
      }
    }
    expect(missing).toEqual([])
  })
})
