import { defineConfig } from '@playwright/test'

const PORT = 3003

export default defineConfig({
  testDir: './test/e2e',
  timeout: 60_000, // Next cold-start is slow
  fullyParallel: false,
  reporter: [['list'], ['html', { outputFolder: 'playwright-report', open: 'never' }]],
  use: { baseURL: `http://localhost:${PORT}` },
  webServer: {
    command: `PORT=${PORT} MODE=block pnpm -F @coraza/example-next dev`,
    url: `http://localhost:${PORT}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
