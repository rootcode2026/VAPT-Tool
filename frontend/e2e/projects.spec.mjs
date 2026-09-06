/**
 * Projects — list for an org-admin, deep-link detail, and creation flow
 * (org-admin can create; the created project is cleaned up via API).
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, API_URL, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.orgAdmin });

test.describe("Projects", () => {
  test("org admin sees projects of their organization", async ({ page }) => {
    await asUser(page, "orgAdmin");
    await page.goto("/projects");
    await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
    const table = page.locator('table[role="table"]');
    await expect(table.getByRole("link", { name: "E2E Alpha One" })).toBeVisible();
    await expect(table.getByRole("link", { name: "E2E Alpha Two" })).toBeVisible();
  });

  test("project detail screen renders overview data", async ({ page }) => {
    await asUser(page, "orgAdmin", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/projects/${IDS.PROJECT_A1}?tab=targets`);
    await expect(
      page.getByRole("heading", { name: "E2E Alpha One" })
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Add Target" })).toBeVisible();
    const table = page.locator('table[role="table"]');
    await expect(table.getByText("e2e-alpha.example.test", { exact: true })).toBeVisible();
  });

  test("org admin can create a project end to end", async ({ page }, testInfo) => {
    testInfo.setTimeout(90_000);
    const name = `E2E UI Created ${Date.now()}`;

    await asUser(page, "orgAdmin");
    await page.goto("/projects");
    await page.getByRole("button", { name: "Create Project" }).click();
    await page.locator("#project-name").fill(name);
    await page
      .getByRole("button", { name: "Create Project", exact: true })
      .last()
      .click();

    // Created project page is the landing destination.
    await expect(page).toHaveURL(/\/projects\/[0-9a-f-]{36}$/);
    await expect(page.getByRole("heading", { name })).toBeVisible();

    // Cleanup via API so the dev database is not polluted with UI leftovers.
    // The token is reused from the storage-state session (no extra login — the
    // backend login endpoint is rate-limited at 20/min and we must not churn it).
    const projectId = new URL(page.url()).pathname.split("/").pop();
    const token = await page.evaluate(
      (key) => window.localStorage.getItem(key),
      "vapt.access_token"
    );
    const del = await fetch(`${API_URL}/api/v1/projects/${projectId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect([200, 204].includes(del.status)).toBeTruthy();
  });
});