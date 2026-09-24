import { expect, test } from '@playwright/test'
import { base, signIn } from './helpers'

// Requires a running platform with the hello module; E2E_OPERATOR_PASSWORD set.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'

test.describe('degradation', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('a module API outage stays inside its area; a gateway outage shows the global page', async ({ page }) => {
    await signIn(page, email, password)
    await page.route('**/api/hello', (r) => r.fulfill({ status: 503, body: '{"reason":"temporarily_unavailable"}', headers: { 'content-type': 'application/json' } }))
    await page.goto(base + '/hello')
    await expect(page.getByTestId('hello-module')).toBeVisible()
    await expect(page.getByTestId('nav-group-auth')).toBeVisible()
    // The gateway API itself down → global outage page.
    await page.route('**/gateway/v1/me', (r) => r.fulfill({ status: 503, body: '{"reason":"temporarily_unavailable"}', headers: { 'content-type': 'application/json' } }))
    await page.goto(base + '/')
    await expect(page.getByTestId('retry')).toBeVisible()
  })
})
