import { expect, test } from '@playwright/test'
import { base, signIn } from './helpers'

// Responsive + CSP contract of the shell frame (specs/013 US1). Runs against a
// full platform; skips without E2E_OPERATOR_PASSWORD.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'

const viewports = [
  { name: 'phone', width: 320, height: 640 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1280, height: 800 },
]

test.describe('shell responsive frame', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  for (const vp of viewports) {
    test(`${vp.name} ${vp.width}px: no horizontal scroll, navigation reachable, zero CSP violations`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      const violations: string[] = []
      await page.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (e) => console.error('CSP:' + (e as SecurityPolicyViolationEvent).violatedDirective + ' ' + (e as SecurityPolicyViolationEvent).blockedURI))
      })
      page.on('console', (m) => { if (m.text().startsWith('CSP:')) violations.push(m.text()) })
      await page.goto(base + '/')
      await signIn(page, email, password)
      await expect(page.locator('main h1')).toBeVisible()
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(overflow, 'no horizontal page scroll').toBeLessThanOrEqual(0)
      expect(await page.locator('[style]').count(), 'no inline style attributes').toBe(0)
      if (vp.width < 1024) {
        await expect(page.getByTestId('nav-home')).toBeHidden()
        await page.getByRole('button', { name: 'Open navigation' }).click()
        await expect(page.getByTestId('nav-home')).toBeVisible()
        await page.keyboard.press('Escape')
      } else {
        await expect(page.getByTestId('nav-home')).toBeVisible()
        await expect(page.getByRole('button', { name: 'Open navigation' })).toHaveCount(0)
      }
      await page.getByTestId('theme-toggle').click()
      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe('freya-dark')
      await page.getByTestId('theme-toggle').click()
      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe('freya-light')
      expect(violations).toEqual([])
    })
  }
})
