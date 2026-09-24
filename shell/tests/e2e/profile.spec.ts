import { expect, test } from '@playwright/test'
import { base, signIn } from './helpers'

// Feature 004: the shell header shows who is signed in and follows profile
// edits made in the auth remote without a sign-out (quickstart §6).
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
// 96x96 RGBA PNG, the same bytes as go-tangra-auth tests/fuzz/testdata/avatars/valid.png.
const avatarPNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAABH0lEQVR4nOzUsQkCQRRF0YdOYZZmZ7YmLNiAG5zknsRJZIPH/Wd7vx7bntt+v+r95/8++Pu33ud6hTnXDGEqAKsArAGwThBWAVgDYJ0grAKwBsA6QVgFYA2AdYKwCsAaAOsEYRWANQDWCcIqAGsArBOEVQDWAFgnCKsArAGwThBWAVgDYJ0grAKwCsAqAGsArBOEVQDWAFgnCKsArAGwThBWAVgDYJ0grAKwBsA6QVgFYA2AdYKwCsAaAOsEYRWANQDWCcIqAGsArBOEVQDWAFgnCKsArAKwCsAaAOsEYRWANQDWCcIqAGsArBOEVQDWAFgnCKsArAGwThBWAVgDYJ0grAKwBsA6QVgFYA2AdYKwCsAaAOsEYRWAfQMAAP//w7EE+Dhh0qIAAAAASUVORK5CYII=',
  'base64',
)

test.describe('shell header', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')

  test('name and avatar update after editing the profile in the auth remote', async ({ page }) => {
    await signIn(page, email, password)
    await expect(page.getByTestId('me-name')).toBeVisible()
    const stamp = String(Date.now()).slice(-5)
    // Navigate inside the shell (a direct /console URL loads the console standalone).
    await page.getByRole('link', { name: 'Security' }).click()
    await expect(page).toHaveURL(/\/console\/security/)
    await expect(page.getByTestId('first-name')).toBeVisible()
    await page.getByTestId('first-name').locator('input').fill('Ops')
    await page.getByTestId('last-name').locator('input').fill(`Person ${stamp}`)
    await page.getByTestId('display-name').locator('input').fill('')
    await page.getByTestId('profile-save').click()
    await expect(page.getByTestId('profile-saved')).toBeVisible()
    // The remote announced the change; the shell refetched /me through a
    // gateway that dropped its cached identity (X-Freya-Identity-Refresh).
    await expect(page.getByTestId('me-name')).toHaveText(`Ops Person ${stamp}`)
    await page.getByTestId('avatar-file').setInputFiles({ name: 'valid.png', mimeType: 'image/png', buffer: avatarPNG })
    await expect(page.getByTestId('avatar-preview').locator('img')).toBeVisible()
    await expect(page.getByTestId('me-avatar').locator('img')).toBeVisible()
    // A full navigation keeps it (the identity is re-exchanged with the new attributes).
    await page.goto(base + '/')
    await expect(page.getByTestId('me-name')).toHaveText(`Ops Person ${stamp}`)
    await expect(page.getByTestId('me-avatar').locator('img')).toBeVisible()
    await page.getByRole('link', { name: 'Security' }).click()
    await expect(page.getByTestId('avatar-remove')).toBeVisible()
    await page.getByTestId('avatar-remove').click()
    await expect(page.getByTestId('me-avatar').locator('img')).toHaveCount(0)
  })
})
