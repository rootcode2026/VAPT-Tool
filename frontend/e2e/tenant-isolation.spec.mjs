/**
 * Tenant isolation — org A users must never see org B data and vice-versa,
 * including direct deep links to cross-tenant projects/findings/scans.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES, apiGet, TOKEN_KEY } from "./support/helpers.mjs";

const PROJECT_A1 = "E2E Alpha One";
const PROJECT_B1 = "E2E Beta One";

test.describe("Tenant isolation / org A admin", () => {
  test.use({ storageState: STATE_FILES.orgAdmin });

  test("org A admin sees only org A projects in the project list", async ({ page }) => {
    await asUser(page, "orgAdmin");
    await page.goto("/projects");
    const table = page.locator('table[role="table"]');
    await expect(table.getByRole("link", { name: PROJECT_A1 })).toBeVisible();
    await expect(page.getByRole("link", { name: PROJECT_B1 })).toHaveCount(0);
  });

  test("org A admin cannot open an org B project via deep link", async ({ page }) => {
    await asUser(page, "orgAdmin");
    await page.goto(`/projects/${IDS.PROJECT_B1}`);
    await expect(page.getByText("Project not found.")).toBeVisible();
  });
});

test.describe("Tenant isolation / org B member", () => {
  test.use({ storageState: STATE_FILES.memberB });

  test("org B member sees only org B projects in the project list", async ({ page }) => {
    await asUser(page, "memberB");
    await page.goto("/projects");
    const table = page.locator('table[role="table"]');
    await expect(table.getByRole("link", { name: PROJECT_B1 })).toBeVisible();
    await expect(page.getByRole("link", { name: PROJECT_A1 })).toHaveCount(0);
  });

  test("org B member cannot open an org A project via deep link", async ({ page }) => {
    await asUser(page, "memberB");
    await page.goto(`/projects/${IDS.PROJECT_A1}`);
    await expect(page.getByText("Project not found.")).toBeVisible();
  });

  test("org B member's findings page never surfaces org A data", async ({ page }) => {
    await asUser(page, "memberB");
    await page.goto(`/findings?project_id=${IDS.PROJECT_A1}`);
    await expect(
      page.getByRole("heading", { name: "Findings Intelligence" })
    ).toBeVisible();
    // The project context quietly falls back to the user's own project — nothing
    // from org A may leak, even when the URL asks for it.
    await expect(page.getByText("E2E Critical SQL Injection")).toHaveCount(0);
  });

  test("org B member's scans page never surfaces org A targets", async ({ page }) => {
    await asUser(page, "memberB");
    await page.goto(`/scans?project_id=${IDS.PROJECT_A1}`);
    await expect(
      page.getByRole("heading", { name: "Scan Operations" })
    ).toBeVisible();
    await expect(page.getByText("e2e-alpha.example.test")).toHaveCount(0);
  });

  test("backend rejects cross-tenant findings requests with 404 (no data leak)", async ({ page }) => {
    await asUser(page, "memberB");
    const token = await page.evaluate(
      (key) => window.localStorage.getItem(key),
      TOKEN_KEY
    );
    const list = await apiGet(`/api/v1/findings?project_id=${IDS.PROJECT_A1}`, token);
    expect(list.status).toBe(404);
    const detail = await apiGet(`/api/v1/findings/${IDS.FINDING_F_CRIT}`, token);
    expect(detail.status).toBe(404);
  });

  test("org B member cannot open an org A finding by id", async ({ page }) => {
    await asUser(page, "memberB");
    await page.goto(`/findings/${IDS.FINDING_F_CRIT}`);
    await expect(page.getByText("Unable to load finding")).toBeVisible();
  });
});

test.describe("Tenant isolation / org A analyst", () => {
  test.use({ storageState: STATE_FILES.analyst });

  test("org A analyst can open org A finding by id", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto(`/findings/${IDS.FINDING_F_CRIT}`);
    await expect(
      page.getByRole("heading", { name: "E2E Critical SQL Injection" })
    ).toBeVisible();
  });
});