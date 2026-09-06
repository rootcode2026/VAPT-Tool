/**
 * Code Security (SAST/SCA/Secrets workspace scanners) — page loads for a
 * project with no code findings and surfaces the appropriate empty state.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("Code Security", () => {
  test("page loads for a project without code scans", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/code-security");
    await expect(
      page.getByRole("heading", { name: "Code Security" })
    ).toBeVisible();
    await expect(page.getByText("No code findings")).toBeVisible();
  });

  test("read-only workspace scanners are surfaced in the UI copy", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/code-security");
    await expect(page.getByText(/Secrets/)).toBeVisible();
  });
});