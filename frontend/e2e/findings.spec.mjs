/**
 * Findings Intelligence — list, deterministic filtering, navigation to detail,
 * and evidence that seeded findings render in the UI.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, XSS_PAYLOAD_TITLE, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("Findings Intelligence", () => {
  test("analyst sees project findings and can open the critical one", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/findings");
    await expect(
      page.getByRole("heading", { name: "Findings Intelligence" })
    ).toBeVisible();

    const table = page.locator('table[role="table"]');
    await table.getByText("E2E Critical SQL Injection").first().click();
    await expect(page).toHaveURL(`/findings/${IDS.FINDING_F_CRIT}`);
    await expect(page.getByRole("heading", { name: "Finding Details" })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "E2E Critical SQL Injection" })
    ).toBeVisible();
    await expect(page.getByText("Critical").first()).toBeVisible();
  });

  test("severity filter narrows the findings inventory", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/findings");
    const table = page.locator('table[role="table"]');
    await expect(table.getByText("E2E Critical SQL Injection")).toBeVisible();

    await page.selectOption('[aria-label="Filter by severity"]', "critical");

    await expect(table.getByText("E2E Critical SQL Injection")).toBeVisible();
    await expect(page.getByText("E2E Medium XSS")).toHaveCount(0);
  });

  test("the stored-XSS finding title is shown as inert text", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/findings");
    const table = page.locator('table[role="table"]');
    await expect(table.getByText(XSS_PAYLOAD_TITLE)).toBeVisible();
  });
});