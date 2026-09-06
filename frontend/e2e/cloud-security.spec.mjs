/**
 * Cloud Security — provider-neutral posture page. The seeded deterministic
 * check pool (CLOUD-001…) renders with no accounts/resources configured.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("Cloud Security", () => {
  test("page loads and renders the deterministic neutral check pool", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/cloud-security");
    await expect(
      page.getByRole("heading", { name: "Cloud Security" })
    ).toBeVisible();
    await expect(page.getByText("CLOUD-001", { exact: false })).toBeVisible();
    await expect(page.getByText("No cloud connections.")).toBeVisible();
  });

  test("page states it is provider-neutral posture", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/cloud-security");
    await expect(page.getByText(/provider-neutral/i)).toBeVisible();
  });
});