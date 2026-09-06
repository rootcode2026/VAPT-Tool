/**
 * Scan Operations — inventory renders seeded scan, and the start-scan workflow
 * submits a real (fast-failing, extern-safe) scan for the fixture target.
 *
 * NOTE: creating a scan enqueues a real Celery task against the .test target,
 * which resolves to NXDOMAIN and fails quickly with no external egress. The
 * resulting failed scan row is harmless leftover data (fixture-purging ignores
 * it) and deliberately proves the pipeline path works end to end through the UI.
 */
import { test, expect } from "@playwright/test";
import { asUser, API_URL, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("Scan Operations", () => {
  test("analyst sees the seeded completed scan with risk grade", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/scans?project_id=${IDS.PROJECT_A1}`);
    await expect(
      page.getByRole("heading", { name: "Scan Operations" })
    ).toBeVisible();
    const table = page.locator('table[role="table"]');
    await expect(table.getByText("e2e-alpha.example.test", { exact: true }).first()).toBeVisible();
    await expect(table.getByText("55 (C)", { exact: true })).toBeVisible();
    await expect(table.getByText("Completed", { exact: true }).first()).toBeVisible();
    // Profile renders via CSS `capitalize`, so the text node is lowercase.
    await expect(table.getByText("quick", { exact: true }).first()).toBeVisible();
  });

  test("recent scans section exists when scans loaded", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/scans?project_id=${IDS.PROJECT_A1}`);
    await expect(
      page.getByRole("heading", { name: "Scan Inventory" })
    ).toBeVisible();
    await expect(page.getByText(/Showing [1-9]\d* of \d+ scans/)).toBeVisible();
  });

  test("analyst can start a real scan against the fixture target", async ({ page }, testInfo) => {
    testInfo.setTimeout(90_000);
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });

    await page.goto(`/scans?project_id=${IDS.PROJECT_A1}&target_id=${IDS.TARGET_A1}`);
    await expect(page.getByRole("button", { name: "Start Scan" })).toBeVisible();

    const [createResponse] = await Promise.all([
      page.waitForResponse(
        (res) =>
          res.url() === `${API_URL}/api/v1/scans` &&
          res.request().method() === "POST",
        { timeout: 30_000 }
      ),
      page.getByRole("button", { name: "Start Scan" }).click(),
    ]);

    expect([200, 201].includes(createResponse.status())).toBeTruthy();
    const body = await createResponse.json();
    expect(body).toHaveProperty("id");

    // No error banner on success.
    await expect(
      page.locator("div.rounded-xl.border-red-900")
    ).toHaveCount(0);
  });
});