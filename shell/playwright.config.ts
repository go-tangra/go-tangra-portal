import { defineConfig } from '@playwright/test'

// E2E_BASE points at the gateway edge; PW_CHANNEL=chrome uses the installed
// Google Chrome instead of Playwright's bundled Chromium.
export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  use: {
    baseURL: process.env.E2E_BASE ?? 'https://localhost:8443',
    ignoreHTTPSErrors: true,
    testIdAttribute: 'data-test',
    ...(process.env.PW_CHANNEL ? { channel: process.env.PW_CHANNEL } : {}),
  },
  reporter: [['list'], ['html', { open: 'never' }]],
})
