import { defineConfig } from "@playwright/test";

/**
 * Playwright E2E security validation for the VAPT-Tool frontend.
 *
 * Requirements before running:
 *   1. The app must be reachable (defaults target the local Docker stack):
 *        PLAYWRIGHT_BASE_URL   -> frontend  (default http://localhost:3000)
 *        PLAYWRIGHT_API_URL    -> backend   (default http://localhost:8000)
 *   2. The E2E seed fixtures must be present (global-setup seeds them).
 *
 * The suite deliberately:
 *   - runs on a single worker (workers: 1) to keep resource usage low and
 *     to keep project-context state predictable;
 *   - uses Chromium only (no cloud / paid browser services are involved);
 *   - retains traces + screenshots ONLY on failure (never in happy path);
 *   - fails fast and clearly in global-setup when the app is unavailable.
 */

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || "http://localhost:3000";
const API_URL = process.env.PLAYWRIGHT_API_URL || "http://localhost:8000";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
  ],
  globalSetup: "./e2e/global-setup.mjs",
  outputDir: "test-results",
  use: {
    baseURL: BASE_URL,
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    ignoreHTTPSErrors: false,
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: undefined,
});

export { BASE_URL, API_URL };