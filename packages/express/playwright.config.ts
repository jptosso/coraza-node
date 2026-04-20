import { defineConfig } from '@playwright/test'

const PORT = 3001

export default defineConfig({
  testDir: './test/e2e',
  timeout: 30_000,
  fullyParallel: false, // one server, serial
  reporter: [['list'], ['html', { outputFolder: 'playwright-report', open: 'never' }]],
  use: {
    baseURL: `http://localhost:${PORT}`,
  },
  webServer: {
    command: `PORT=${PORT} MODE=block pnpm -F @coraza/example-express dev`,
    url: `http://localhost:${PORT}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
})
