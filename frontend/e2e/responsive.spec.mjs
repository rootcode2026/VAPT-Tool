/**
 * Responsive — the app shell degrades cleanly to a mobile drawer, and
 * every DataTable switches to its stacked mobile layout.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("Responsive layout", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("mobile shell uses a navigation drawer", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });

    // Desktop sidebar hidden at this width; hamburger shown instead.
    await expect(page.getByRole("link", { name: "Dashboard" })).toBeHidden();
    await expect(
      page.getByRole("button", { name: "Open navigation" })
    ).toBeVisible();

    await page.getByRole("button", { name: "Open navigation" }).click();
    const drawer = page.locator("div.fixed.inset-0.z-50 > aside");
    await expect(drawer.getByRole("link", { name: "Findings" })).toBeVisible();
    await drawer.getByRole("button", { name: "Close navigation" }).click();
    await expect(drawer.getByRole("link", { name: "Findings" })).toBeHidden();
  });

  test("findings inventory switches to the stacked mobile layout", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/findings");

    const mobileList = page.locator("ul.space-y-3").first();
    const desktopTable = page.locator('table[role="table"]');
    await expect(mobileList).toBeVisible();
    await expect(desktopTable).toBeHidden();

    await expect(mobileList.getByText("E2E Critical SQL Injection")).toBeVisible();
  });

  test("scan operations remain usable on a phone screen", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/scans?project_id=${IDS.PROJECT_A1}`);

    await expect(
      page.getByRole("heading", { name: "Scan Operations" })
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Start Scan" })).toBeVisible();
  });
});