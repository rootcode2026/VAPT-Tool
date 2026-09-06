/**
 * Role-based access control — the backend is authoritative and the UI must
 * surface its decisions (403 details or default messages) without crashing.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

const FORBIDDEN_ANALYST = /Insufficient permissions: requires analyst to execute scans/i;
const FORBIDDEN_TARGET = /Insufficient permissions: requires analyst or project_admin to create targets/i;

test.describe("RBAC / viewer", () => {
  test.use({ storageState: STATE_FILES.viewer });

  test("viewer cannot start a scan and sees the backend 403 detail", async ({ page }) => {
    await asUser(page, "viewer", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/scans?project_id=${IDS.PROJECT_A1}`);
    await expect(page.getByRole("heading", { name: "Scan Operations" })).toBeVisible();
    await page.getByRole("button", { name: "Start Scan" }).click();
    await expect(page.getByText(FORBIDDEN_ANALYST).first()).toBeVisible();
  });

  test("viewer cannot add a target to a project", async ({ page }) => {
    await asUser(page, "viewer", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/projects/${IDS.PROJECT_A1}?tab=targets`);
    await expect(page.getByRole("button", { name: "Add Target" })).toBeVisible();
    await page.getByRole("button", { name: "Add Target" }).click();
    await page.locator("#target-value").fill("blocked.example.test");
    await page.getByRole("button", { name: "Add Target" }).last().click();
    // The frontend intentionally hides backend 403 details behind a generic
    // message (see lib/api/client.js publicErrorMessage).
    await expect(
      page.getByText("You are not authorized to view this resource.")
    ).toBeVisible();
  });
});

test.describe("RBAC / analyst", () => {
  test.use({ storageState: STATE_FILES.analyst });

  test("analyst cannot create a project and sees the default 403 message", async ({ page }) => {
    await asUser(page, "analyst");
    await page.goto("/projects");
    await page.getByRole("button", { name: "Create Project" }).click();
    await page.locator("#project-name").fill("RBAC Should Block Me");
    await page.getByRole("button", { name: "Create Project", exact: true }).last().click();
    await expect(
      page.getByText("You are not authorized to view this resource.")
    ).toBeVisible();
  });

  test("non-super-admin cannot open the admin dashboard", async ({ page }) => {
    await asUser(page, "analyst");
    await page.goto("/admin");
    await expect(page.getByText("Unable to load admin data.")).toBeVisible();
  });
});

test.describe("RBAC / project admin", () => {
  test.use({ storageState: STATE_FILES.projectAdmin });

  test("project admin can reach an enabled start-scan form", async ({ page }) => {
    await asUser(page, "projectAdmin", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/scans?project_id=${IDS.PROJECT_A1}&target_id=${IDS.TARGET_A1}`);
    await expect(page.getByRole("button", { name: "Start Scan" })).toBeVisible();
    // project_admin has permission to execute scans, so the submit button must
    // not be blocked client-side.
    await expect(page.getByRole("button", { name: "Start Scan" })).toBeEnabled();
  });
});