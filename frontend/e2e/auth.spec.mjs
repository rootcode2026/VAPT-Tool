/**
 * Authentication flow — real UI login, invalid credentials, session expiry,
 * redirects, and logout.
 *
 * Two describes have no storageState (they exercise the real login form or
 * anonymous redirects); the signed-in describes reuse pre-generated
 * storageState files so the suite stays within the backend login rate limit.
 */
import { test, expect } from "@playwright/test";
import { loginByForm, asUser, USERS, TOKEN_KEY, STATE_FILES } from "./support/helpers.mjs";

test.describe("Authentication / login form", () => {
  test("valid credentials sign in through the real login form", async ({ page }, testInfo) => {
    testInfo.setTimeout(60_000);
    await loginByForm(page, USERS.analyst.email, USERS.analyst.password);
    await expect(page).toHaveURL(/\/dashboard$/);
  });

  test("invalid credentials stay on the login page with a generic error", async ({ page }) => {
    await page.goto("/login");
    await page.locator("#email").fill(USERS.analyst.email);
    await page.locator("#password").fill("definitely-wrong");
    await page.getByRole("button", { name: "Sign In" }).click();
    await expect(page.getByText("Invalid email or password.")).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
  });

  test("unauthenticated users are redirected to /login with a next parameter", async ({ page }) => {
    await page.goto("/projects");
    await expect(page).toHaveURL(/\/login\?next=/);
  });
});

test.describe("Authentication / signed-in session", () => {
  test.use({ storageState: STATE_FILES.analyst });

  test("signing out returns to /login and protects pages afterwards", async ({ page }) => {
    await asUser(page, "analyst");
    await page.getByRole("button", { name: "Sign out" }).first().click();
    await expect(page).toHaveURL(/\/login(\?next=.*)?$/);
    await expect(page.evaluate((key) => localStorage.getItem(key), TOKEN_KEY)).resolves.toBeNull();
    await page.goto("/findings");
    await expect(page).toHaveURL(/\/login\?next=/);
  });

  test("a removed token forces re-authentication on the next page load", async ({ page }) => {
    await asUser(page, "analyst");
    await page.evaluate((key) => window.localStorage.removeItem(key), TOKEN_KEY);
    // The client-side redirect aborts this goto — that abort IS the redirect.
    await page.goto("/projects").catch(() => {});
    await expect(page).toHaveURL(/\/login\?next=/);
  });
});

test.describe("Authentication / super admin", () => {
  test.use({ storageState: STATE_FILES.superAdmin });

  test("super admin lands on the dashboard and sees the admin nav", async ({ page }) => {
    await asUser(page, "superAdmin");
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.getByRole("link", { name: "Admin Dashboard" })).toBeVisible();
  });
});