/**
 * Super Admin — platform-wide admin console is reachable only for the
 * platform super admin and exposes the admin nav surface.
 */
import { test, expect } from "@playwright/test";
import { asUser, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.superAdmin });

test.describe("Super Admin", () => {
  test("super admin can open the platform admin dashboard", async ({ page }) => {
    await asUser(page, "superAdmin");
    await page.goto("/admin");
    await expect(
      page.getByRole("heading", { name: "Super Admin Dashboard" })
    ).toBeVisible();
  });

  test("admin navigation is visible for super admin", async ({ page }) => {
    await asUser(page, "superAdmin");
    await page.goto("/dashboard");
    await expect(page.getByRole("link", { name: "Admin Dashboard" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Organizations" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Users" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Scanner Fleet" })).toBeVisible();
    await expect(page.getByRole("link", { name: "System Health" })).toBeVisible();
  });
});