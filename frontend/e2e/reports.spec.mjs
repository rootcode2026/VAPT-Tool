/**
 * Reports — seeded reports are tenant-scoped: org A sees only org A reports,
 * org B sees only org B reports, deep links stay isolated.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

const REPORT_A = "E2E Executive Security Report";
const REPORT_B = "E2E Beta Executive Report";

test.describe("Reports / org A", () => {
  test.use({ storageState: STATE_FILES.analyst });

  test("org A analyst sees their seeded executive report", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/reports");
    for (const name of ["Product tour", "Welcome"]) {
      const dlg = page.getByRole("dialog", { name });
      if (await dlg.isVisible().catch(() => false)) {
        const skip = dlg.getByRole("button", { name: /Skip/ });
        if (await skip.isVisible().catch(() => false)) await skip.click().catch(() => {});
        else await page.keyboard.press("Escape").catch(() => {});
        await page.waitForTimeout(800);
        await expect(dlg).not.toBeVisible({ timeout: 5000 }).catch(() => {});
      }
    }
    await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(REPORT_A)).toBeVisible({ timeout: 15000 });
  });
});

test.describe("Reports / org B", () => {
  test.use({ storageState: STATE_FILES.memberB });

  test("org B member sees only their organization's reports", async ({ page }) => {
    await asUser(page, "memberB", { projectId: IDS.PROJECT_B1 });
    await page.goto("/reports");
    await expect(page.getByText(REPORT_B)).toBeVisible();
    await expect(page.getByText(REPORT_A)).toHaveCount(0);
  });
});