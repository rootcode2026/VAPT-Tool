/**
 * AI Security Analyst — the assistant is read-only/advisory; when AI is not
 * enabled the page must say so plainly instead of advertising unavailable
 * functionality.
 */
import { test, expect } from "@playwright/test";
import { asUser, IDS, STATE_FILES } from "./support/helpers.mjs";

test.use({ storageState: STATE_FILES.analyst });

test.describe("AI Security Analyst", () => {
  test("page loads for an analyst with a selected project", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/ai");
    await expect(
      page.getByRole("heading", { name: "AI Security Analyst" })
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "New Conversation" })
    ).toBeVisible();
  });

  test("disabled state is transparently communicated", async ({ page }) => {
    await asUser(page, "analyst", { projectId: IDS.PROJECT_A1 });
    await page.goto("/ai");
    await expect(
      page.getByText(/AI is disabled.*Platform works normally without AI/)
    ).toBeVisible();
  });
});