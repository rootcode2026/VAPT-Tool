/**
 * Shared helpers + deterministic fixture constants for the E2E suite.
 *
 * The fixture accounts and ids below are created by the backend seeder
 * (backend/scripts/seed_e2e_fixtures.py). Never use production/real
 * credentials here.
 *
 * Authentication strategy: the suite must NOT hammer the login endpoint
 * (backend rate limit: 20 logins / minute / IP — a security control we must
 * keep). global-setup logs each fixture user in exactly once and writes a
 * Playwright storageState file per user; every spec loads the storageState for
 * the user it needs instead of logging in per test.
 */
import { expect } from "@playwright/test";

export const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || "http://localhost:3000";
export const API_URL = process.env.PLAYWRIGHT_API_URL || "http://localhost:8000";

export const E2E_PASSWORD = "E2eTestPass!2026";

export const USERS = {
  superAdmin: { email: "e2e.superadmin@test.local", password: E2E_PASSWORD },
  orgAdmin: { email: "e2e.orgadmin@test.local", password: E2E_PASSWORD },
  projectAdmin: { email: "e2e.projectadmin@test.local", password: E2E_PASSWORD },
  analyst: { email: "e2e.analyst@test.local", password: E2E_PASSWORD },
  viewer: { email: "e2e.viewer@test.local", password: E2E_PASSWORD },
  memberB: { email: "e2e.memberb@test.local", password: E2E_PASSWORD },
};

/**
 * storageState files written by global-setup (one login per user, then reused
 * across every test). Paths are relative to the Playwright config dir.
 */
export const STATE_DIR = "./test-results";
export const STATE_FILES = {
  superAdmin: `${STATE_DIR}/state-superAdmin.json`,
  orgAdmin: `${STATE_DIR}/state-orgAdmin.json`,
  projectAdmin: `${STATE_DIR}/state-projectAdmin.json`,
  analyst: `${STATE_DIR}/state-analyst.json`,
  viewer: `${STATE_DIR}/state-viewer.json`,
  memberB: `${STATE_DIR}/state-memberB.json`,
};

export const IDS = {
  ORG_A: "e2eaaaaa-0000-4000-8000-000000000001",
  ORG_B: "e2eaaaaa-0000-4000-8000-000000000002",
  PROJECT_A1: "e2eaaaaa-0000-4000-8000-0000000000a1",
  PROJECT_A2: "e2eaaaaa-0000-4000-8000-0000000000a2",
  PROJECT_B1: "e2eaaaaa-0000-4000-8000-0000000000b1",
  TARGET_A1: "e2eaaaaa-0000-4000-8000-0000000000t1",
  TARGET_B1: "e2eaaaaa-0000-4000-8000-0000000000t3",
  SCAN_A1: "e2eaaaaa-0000-4000-8000-0000000000s1",
  SCAN_B1: "e2eaaaaa-0000-4000-8000-0000000000s2",
  FINDING_F_CRIT: "e2eaaaaa-0000-4000-8000-0000000000f1",
  FINDING_F_HIGH: "e2eaaaaa-0000-4000-8000-0000000000f2",
  FINDING_F_MED: "e2eaaaaa-0000-4000-8000-0000000000f3",
  FINDING_F_LOW: "e2eaaaaa-0000-4000-8000-0000000000f4",
  FINDING_F_INFO: "e2eaaaaa-0000-4000-8000-0000000000f5",
  FINDING_F_XSS: "e2eaaaaa-0000-4000-8000-0000000000f6",
  FINDING_F_B1: "e2eaaaaa-0000-4000-8000-0000000000f7",
};

export const TOKEN_KEY = "vapt.access_token";
export const PROJECT_STORAGE_KEY = "vapt.selectedProjectId";

/** Inert stored-XSS payload planted as a finding title by the seeder. */
export const XSS_PAYLOAD_TITLE =
  'E2E XSS <img src=x onerror="window.__E2E_XSS_FIRED__=1"> Title';

/**
 * Log in through the real login form (UI). Used only by tests whose purpose
 * is the authentication flow itself — these are few, so the login rate limit
 * stays intact.
 */
export async function loginByForm(page, email, password) {
  await page.goto("/login");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign In" }).click();
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeVisible({
    timeout: 30_000,
  });
}

/** Log in via the API and inject the token into localStorage (fast path). */
export async function loginByApi(page, email, password) {
  const token = await apiLogin(email, password);
  await page.addInitScript(
    ([key, value]) => {
      try {
        window.localStorage.setItem(key, value);
      } catch {
        // ignore
      }
    },
    [TOKEN_KEY, token]
  );
  await page.goto("/dashboard");
  // Wait for a viewport-independent post-login signal: the dashboard route's
  // main content. (The sidebar link is hidden on small screens.)
  await page.waitForURL("**/dashboard");
  await expect(page.getByRole("main")).toBeVisible({ timeout: 30_000 });
}

/**
 * Prepare a page for `userKey`. Authentication comes from the pre-generated
 * storageState (see STATE_FILES); this helper only fixes the project context
 * in sessionStorage and drives the browser to the dashboard.
 */
export async function asUser(page, userKey, { projectId } = {}) {
  const user = USERS[userKey];
  if (!user) throw new Error(`Unknown E2E user: ${userKey}`);
  if (projectId) {
    await page.addInitScript(
      ([key, id]) => {
        try {
          window.sessionStorage.setItem(key, id);
        } catch {
          // ignore
        }
      },
      [PROJECT_STORAGE_KEY, projectId]
    );
  }
  await page.goto("/dashboard");
  await expect(page.getByRole("main")).toBeVisible({ timeout: 30_000 });
}

/** Generic backend API helper for assertions that need a raw response. */
export async function apiGet(path, token) {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return { status: response.status, body: await response.json().catch(() => null) };
}

/**
 * Acquire a backend token directly. Backs off when the backend login rate
 * limiter responds 429 (20/min/IP). Used sparingly by global-setup and
 * cleanup helpers.
 */
export async function apiLogin(email, password) {
  const deadline = Date.now() + 75_000;
  for (;;) {
    const response = await fetch(`${API_URL}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (response.status === 429) {
      if (Date.now() > deadline) {
        throw new Error(`[e2e] Backend login rate limit held for too long (${email})`);
      }
      // Back off until the limiter (20/min/IP) window rolls over.
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      continue;
    }
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.access_token) {
      throw new Error(`[e2e] apiLogin failed (${response.status}) for ${email}`);
    }
    return body.access_token;
  }
}