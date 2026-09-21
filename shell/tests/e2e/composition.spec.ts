import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { base, signIn } from './helpers'

// Runs against a full platform (gateway + auth in gateway mode + hello module
// with its remote). Set E2E_BASE (default https://localhost:8443),
// E2E_OPERATOR_EMAIL and E2E_OPERATOR_PASSWORD; the operator must already be
// bootstrapped (the helper enrols TOTP on first sign-in).
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'

test.describe.configure({ mode: 'serial' })

test.describe('shell composition', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('signs in once, composes remotes without reloads, isolates failures', async ({ page }) => {
    const errors: string[] = []
    page.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('Content Security Policy') && !m.text().includes('401')) errors.push(m.text()) })
    page.on('pageerror', (e) => errors.push('pageerror: ' + e.message))
    await page.goto(base + '/')
    // Anonymous → auth remote sign-in page served through the gateway.
    await expect(page).toHaveURL(/\/console\/signin/)
    await signIn(page, email, password)
    await expect(page.getByTestId('nav-group-auth')).toBeVisible()
    // From here on, navigation between remotes must not load a new document.
    // Module menus expand on click; entries are their sub-items.
    const loads: string[] = []
    page.on('domcontentloaded', () => loads.push(page.url()))
    await page.getByTestId('nav-group-hello').click()
    await page.getByTestId('nav-hello').click()
    await expect(page.getByTestId('hello-module')).toBeVisible()
    await expect(page.getByTestId('can')).toBeVisible()
    await page.getByTestId('nav-group-auth').click()
    await page.getByTestId('nav-auth').first().click()
    await expect(page).toHaveURL(/\/console\//)
    await expect(page.locator('main').getByText(/users/i).first()).toBeVisible()
    expect(loads, 'document loads between remotes').toEqual([])
    expect(errors, 'browser errors').toEqual([])
    // Accessibility of the composed page.
    const results = await new AxeBuilder({ page }).analyze()
    expect(results.violations.filter((v) => v.impact === 'critical')).toEqual([])
  })

  test('a broken remote shows an error card only in its area', async ({ page }) => {
    await signIn(page, email, password)
    await page.route('**/m/hello/mf-manifest.json', (r) => r.fulfill({ status: 503, body: '{"reason":"temporarily_unavailable"}' }))
    await page.goto(base + '/hello')
    await expect(page.getByTestId('nav-home')).toBeVisible()
    await expect(page.getByTestId('nav-group-auth')).toBeVisible()
    await expect(page.getByTestId('hello-module')).not.toBeVisible()
  })

  test('sign-out anywhere returns every module area to signed-out', async ({ page }) => {
    await signIn(page, email, password)
    await page.goto(base + '/console/security')
    await page.getByTestId('signout').click()
    await expect(page).toHaveURL(/\/console\/signin/)
    await page.goto(base + '/hello')
    await expect(page).toHaveURL(/\/console\/signin/)
  })
})
