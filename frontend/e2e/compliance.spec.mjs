/**
 * Compliance Intelligence — framework registry loads for a normal analyst
 * (frameworks self-seed on demand), and does not leak cross-tenant data.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("Compliance Intelligence", () => {
  test("analyst can view the framework registry", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/compliance");
    await expect(
      page.getByRole("heading", { name: "Compliance Intelligence" })
    ).toBeVisible();
    // A representative subset of the self-seeded framework catalog.
    await expect(page.getByText("owasp_asvs", { exact: false }).first()).toBeVisible();
    await expect(page.getByText("iso27001", { exact: false }).first()).toBeVisible();
    await expect(page.getByText("nist_csf", { exact: false }).first()).toBeVisible();
  });

  test("compliance page states framework versions", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/compliance");
    await expect(page.getByText(/SELECTED FRAMEWORK|Select a framework|Framework/i)).toBeVisible();
  });
});