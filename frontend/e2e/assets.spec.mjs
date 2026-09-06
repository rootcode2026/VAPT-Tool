/**
 * Asset Intelligence + Attack Surface — seeded assets for the fixture target
 * are discoverable and cross-navigable.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

const ASSET_VALUE = "e2e-alpha.example.test";

test.describe("Asset Intelligence", () => {
  test("analyst sees fixture assets for the project", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/assets");
    await expect(
      page.getByRole("heading", { name: "Asset Intelligence", exact: true })
    ).toBeVisible();
    // Scope to the visible desktop table (the mobile <ul> copy is hidden at
    // desktop width) and use exact matching to skip the webapp URL cell.
    const table = page.locator('table[role="table"]');
    await expect(table.getByText(ASSET_VALUE, { exact: true })).toBeVisible();
    await expect(
      table.getByText("webapp", { exact: true }).first()
    ).toBeVisible();
  });

  test("attack surface page renders the exposed asset", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/attack-surface");
    await expect(
      page.getByRole("heading", { name: "Attack Surface", exact: true })
    ).toBeVisible();
    const table = page.locator('table[role="table"]').first();
    await expect(table.getByText(ASSET_VALUE, { exact: true })).toBeVisible();
  });
});