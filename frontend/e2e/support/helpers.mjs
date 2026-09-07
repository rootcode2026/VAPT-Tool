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
import { createHmac } from "node:crypto";

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
  pwreset: { email: "e2e.pwreset@test.local", password: E2E_PASSWORD },
  onboard: { email: "e2e.onboard@test.local", password: E2E_PASSWORD },
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
  pwreset: `${STATE_DIR}/state-pwreset.json`,
  onboard: `${STATE_DIR}/state-onboard.json`,
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

export async function apiPost(path, token, body) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API_URL}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json().catch(() => null), headers: response.headers };
}
export async function apiPatch(path, token, body) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API_URL}${path}`, { method: "PATCH", headers, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json().catch(() => null), headers: response.headers };
}

// MFA helpers
export async function apiMfaSetup(token) {
  return apiPost("/api/v1/auth/mfa/setup", token, {});
}
export async function apiMfaSetupVerify(token, code) {
  return apiPost("/api/v1/auth/mfa/setup/verify", token, { code });
}
export async function apiMfaDisable(token, password, code) {
  return apiPost("/api/v1/auth/mfa/disable", token, { password, code });
}
export async function apiMfaRegenerate(token, password, code) {
  return apiPost("/api/v1/auth/mfa/recovery-codes/regenerate", token, { password, code });
}
export async function apiMfaStatus(token) {
  return apiGet("/api/v1/auth/mfa/status", token);
}
export async function apiForgotPassword(email) {
  const res = await fetch(`${API_URL}/api/v1/auth/forgot-password`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }) });
  return { status: res.status, body: await res.json().catch(() => null) };
}
export async function apiResetPassword(token, new_password, confirm_password) {
  const res = await fetch(`${API_URL}/api/v1/auth/reset-password`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token, new_password, confirm_password }) });
  return { status: res.status, body: await res.json().catch(() => null) };
}
export async function apiChangePassword(token, current_password, new_password, confirm_password) {
  return apiPost("/api/v1/auth/change-password", token, { current_password, new_password, confirm_password });
}
export async function apiLoginRaw(email, password) {
  const res = await fetch(`${API_URL}/api/v1/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
  return { status: res.status, body: await res.json().catch(() => null) };
}
export async function apiMfaChallenge(mfaToken, code) {
  const res = await fetch(`${API_URL}/api/v1/auth/mfa/challenge`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mfa_token: mfaToken, code }) });
  return { status: res.status, body: await res.json().catch(() => null) };
}
export async function apiOnboardingStatus(token) {
  return apiGet("/api/v1/onboarding/status", token);
}
export async function apiOnboardingStart(token) {
  return apiPost("/api/v1/onboarding/start", token, {});
}
export async function apiOnboardingProgress(token, step) {
  return apiPost("/api/v1/onboarding/progress", token, { current_step: step });
}
export async function apiOnboardingSkip(token) {
  return apiPost("/api/v1/onboarding/skip", token, {});
}
export async function apiOnboardingComplete(token) {
  return apiPost("/api/v1/onboarding/complete", token, {});
}
export async function apiOnboardingRestart(token) {
  return apiPost("/api/v1/onboarding/restart", token, {});
}

// Compute TOTP (RFC 6238, 6 digits, 30s) using Node crypto — for Playwright Node process
export function totpNow(secret) {
  const b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) {
    const v = b32.indexOf(c);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, "0");
  }
  const key = Buffer.alloc(Math.floor(bits.length / 8));
  for (let i = 0; i < key.length; i++) key[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const counter = Math.floor(Date.now() / 30000);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter), 0);
  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}

/**
 * Acquire a backend token directly. Backs off when the backend login rate
 * limiter responds 429 (20/min/IP). Used sparingly by global-setup and
 * cleanup helpers.
 */
export async function apiLogin(email, password) {
  const deadline = Date.now() + 130_000;
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
      // Rate limit window is 60s; wait for it to roll over without hammering
      await new Promise((resolve) => setTimeout(resolve, 65_000));
      continue;
    }
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.access_token) {
      // Handle MFA required case — for storageState we need to complete MFA if user has it enabled
      // For now, if mfa_required, we cannot return access_token; caller should handle via apiLoginRaw
      // To keep backward compat, try to detect and fail with clear message
      if (body.mfa_required) {
        throw new Error(`[e2e] apiLogin mfa_required for ${email} — use apiLoginRaw + challenge`);
      }
      throw new Error(`[e2e] apiLogin failed (${response.status}) for ${email}`);
    }
    return body.access_token;
  }
}