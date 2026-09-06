/**
 * Security hardening — client-side hygiene:
 *   - inert result: a stored-XSS finding payload must never execute;
 *   - bearer token lives only in localStorage, and never leaks to cookies
 *     or the rendered DOM;
 *   - API errors are generic (no stack traces leaked);
 *   - known limitation guard: the frontend currently emits no CSP/HSTS
 *     headers (no Next.js middleware). Documented as a known limitation in
 *     docs/PLAYWRIGHT_MCP.md and docs/PROJECT_STATE.md. This assertion is
 *     intentional: it will start failing the moment edge-layer/middleware
 *     hardening lands, which is exactly the signal we want.
 */
import { test, expect } from "@playwright/test";
import {
  asUser,
  IDS,
  XSS_PAYLOAD_TITLE,
  TOKEN_KEY,
  API_URL,
  BASE_URL,
  USERS,
  STATE_FILES,
} from "./support/helpers.mjs";

const XSS_FLAG = "__E2E_XSS_FIRED__";

test.describe("Security hardening / XSS & session (org A analyst)", () => {
  test.use({ storageState: STATE_FILES.analyst });

  test("stored-XSS finding title renders as inert text and never executes", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/findings");
    const table = page.locator('table[role="table"]');
    await table.getByText(XSS_PAYLOAD_TITLE).first().click();
    await page.waitForURL(`**/findings/${IDS.FINDING_F_XSS}`);

    await expect(page.getByRole("heading", { name: "Finding Details" })).toBeVisible();
    // The raw payload is displayed verbatim as escaped text, not parsed.
    await expect(page.getByRole("heading", { name: XSS_PAYLOAD_TITLE })).toBeVisible();
    // No injected <img> was parsed into a real element.
    await expect(page.locator("img[onerror]")).toHaveCount(0);
    // And the onerror callback never ran on this page.
    const fired = await page.evaluate((flag) => window[flag] ?? 0, XSS_FLAG);
    expect(fired).toBe(0);
  });
});

test.describe("Security hardening / token hygiene (org A org-admin)", () => {
  test.use({ storageState: STATE_FILES.orgAdmin });

  test("access token lives only in localStorage — no auth cookie, no DOM leak", async ({ page }) => {
    await asUser(page, "orgAdmin", { projectId: IDS.PROJECT_A1 });

    const token = await page.evaluate((key) => window.localStorage.getItem(key), TOKEN_KEY);
    expect(token).toBeTruthy();

    // No cookie carries the token.
    const cookies = await page.context().cookies();
    for (const cookie of cookies) {
      expect(cookie.value).not.toContain(token);
    }

    // The token never appears in rendered page text (any page).
    const bodyText = await page.evaluate(() => document.body.innerText);
    expect(bodyText).not.toContain(token);
  });
});

test.describe("Security hardening / anonymous errors", () => {
  test("unauthenticated API calls return a generic 401 without stack traces", async ({ page }) => {
    const response = await page.request.get(`${API_URL}/api/v1/projects`);
    expect(response.status()).toBe(401);
    const body = await response.json().catch(() => ({}));
    expect(body.detail).toBeTruthy();
    const rendered = JSON.stringify(body);
    expect(rendered).not.toContain("Traceback");
    expect(rendered).not.toMatch(/File ".*", line \d+/);
  });

  test("wrong credentials never leak internal error details", async ({ page }) => {
    const response = await page.request.post(`${API_URL}/api/v1/auth/login`, {
      data: { email: USERS.analyst.email, password: "nope" },
    });
    // 401 (bad creds) or 429 (rate limiter) — both are valid, leak-free
    // responses; the point is no internal traceback/source ever surfaces.
    expect([401, 429].includes(response.status())).toBeTruthy();
    const body = await response.json().catch(() => ({}));
    const rendered = JSON.stringify(body);
    expect(rendered).not.toContain("Traceback");
    expect(rendered).not.toMatch(/File ".*", line \d+/);
  });

  test("known limitation guard: no CSP/HSTS headers are emitted by the frontend yet", async ({ page }) => {
    const response = await page.request.get(`${BASE_URL}/login`);
    const headers = response.headers();
    for (const header of [
      "content-security-policy",
      "strict-transport-security",
      "x-frame-options",
      "x-content-type-options",
    ]) {
      expect(headers[header]).toBeUndefined();
    }
  });
});