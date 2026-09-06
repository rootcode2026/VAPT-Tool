/**
 * DAST — advanced active-testing page surfaces its bounded/safe posture and
 * loads cleanly for a project with no DAST configuration.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("DAST", () => {
  test("page loads with safety policy surfaced", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/dast");
    await expect(
      page.getByRole("heading", { name: "Advanced DAST" })
    ).toBeVisible();
    await expect(page.getByText(/SSRF protected/i)).toBeVisible();
  });

  test("page bounds to allowed domains", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/dast");
    await expect(page.getByText(/bounded to allowed domains/i)).toBeVisible();
  });
});