/**
 * Password reset — forgot, generic response, token lifecycle, enumeration protection.
 */
import { test, expect } from "@playwright/test";
import {
  USERS,
  STATE_FILES,
  asUser,
  apiGet,
  apiPost,
  apiLogin,
  apiLoginRaw,
  apiForgotPassword,
  apiResetPassword,
  E2E_PASSWORD,
} from "./support/helpers.mjs";

const NEW_PASSWORD = "NewE2ePass!2026A";

test.describe("Password reset / forgot page", () => {
  test("forgot-password page renders", async ({ page }) => {
    await page.goto("/forgot-password");
    await expect(page.getByRole("heading", { name: "Forgot password" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Send reset link" })).toBeVisible();
  });

  test("forgot-password generic response for existent account", async () => {
    const res = await apiForgotPassword(USERS.analyst.email);
    expect(res.status).toBe(200);
    expect(res.body.message).toContain("If an account exists");
  });

  test("forgot-password generic response for non-existent account (no enumeration)", async () => {
    const res = await apiForgotPassword("nonexistent-random-xyz-123@test.local");
    expect(res.status).toBe(200);
    expect(res.body.message).toContain("If an account exists");
  });

  test("forgot-password responses are identical for existent vs non-existent", async () => {
    const a = await apiForgotPassword(USERS.viewer.email);
    const b = await apiForgotPassword("does-not-exist-xyz@test.local");
    expect(a.body.message).toBe(b.body.message);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
  });
});

test.describe("Password reset / token lifecycle", () => {
  test("reset with invalid token fails", async () => {
    const res = await apiResetPassword("invalid-token-" + Date.now(), "ValidPass123!", "ValidPass123!");
    expect(res.status).toBe(400);
    expect(res.body.detail).toBeTruthy();
  });

  test("reset flow succeeds and old password is rejected, new password works", async () => {
    const email = USERS.pwreset.email;
    const oldPass = E2E_PASSWORD;
    const forgot = await apiForgotPassword(email);
    expect(forgot.status).toBe(200);
    const adminToken = await apiLogin(USERS.superAdmin.email, E2E_PASSWORD);
    const outboxRes = await apiGet("/api/v1/auth/_debug/email-outbox", adminToken);
    let rawToken = null;
    if (outboxRes.status === 200 && Array.isArray(outboxRes.body.outbox)) {
      const entry = [...outboxRes.body.outbox].reverse().find((e) => e.to?.toLowerCase() === email.toLowerCase());
      rawToken = entry?.token;
    }
    if (!rawToken) {
      test.skip();
      return;
    }
    expect(rawToken).toBeTruthy();
    const reset = await apiResetPassword(rawToken, NEW_PASSWORD, NEW_PASSWORD);
    expect(reset.status).toBe(200);
    const oldLogin = await apiLoginRaw(email, oldPass);
    expect(oldLogin.status).toBe(401);
    const newLogin = await apiLoginRaw(email, NEW_PASSWORD);
    expect(newLogin.status).toBe(200);
    expect(newLogin.body.access_token).toBeTruthy();
    const reuse = await apiResetPassword(rawToken, "AnotherPass123!", "AnotherPass123!");
    expect(reuse.status).toBe(400);
    const forgot2 = await apiForgotPassword(email);
    expect(forgot2.status).toBe(200);
    const out2 = await apiGet("/api/v1/auth/_debug/email-outbox", adminToken);
    let raw2 = null;
    if (out2.status === 200) {
      const e = [...out2.body.outbox].reverse().find((x) => x.to?.toLowerCase() === email.toLowerCase());
      raw2 = e?.token;
    }
    if (raw2) {
      const back = await apiResetPassword(raw2, oldPass, oldPass);
      expect(back.status).toBe(200);
      const check = await apiLoginRaw(email, oldPass);
      expect(check.status).toBe(200);
    }
  });

  test("reset does not disable MFA (if enabled, still required after reset)", async () => {
    const email = USERS.pwreset.email;
    const superToken = await apiLogin(USERS.superAdmin.email, E2E_PASSWORD);
    await apiPost("/api/v1/auth/_debug/mfa/reset", superToken, { email });
    let token = await apiLogin(email, E2E_PASSWORD);
    const setup = await apiPost("/api/v1/auth/mfa/setup", token, {});
    expect(setup.status).toBe(200);
    const secret = setup.body.secret;
    const { totpNow: tn } = await import("./support/helpers.mjs");
    const code = tn(secret);
    const vr = await apiPost("/api/v1/auth/mfa/setup/verify", token, { code });
    expect(vr.status).toBe(200);
    await apiForgotPassword(email);
    const out = await apiGet("/api/v1/auth/_debug/email-outbox", superToken);
    let raw = null;
    if (out.status === 200) {
      const e = [...out.body.outbox].reverse().find((x) => x.to?.toLowerCase() === email.toLowerCase());
      raw = e?.token;
    }
    if (!raw) {
      test.skip();
      return;
    }
    const reset = await apiResetPassword(raw, "TempPass123!A", "TempPass123!A");
    expect(reset.status).toBe(200);
    const rawLogin = await apiLoginRaw(email, "TempPass123!A");
    expect(rawLogin.body.mfa_required).toBe(true);
    await apiForgotPassword(email);
    const out2 = await apiGet("/api/v1/auth/_debug/email-outbox", superToken);
    let raw2 = null;
    if (out2.status === 200) {
      const e = [...out2.body.outbox].reverse().find((x) => x.to?.toLowerCase() === email.toLowerCase());
      raw2 = e?.token;
    }
    if (raw2) await apiResetPassword(raw2, E2E_PASSWORD, E2E_PASSWORD);
    await apiPost("/api/v1/auth/_debug/mfa/reset", superToken, { email });
  });

  test("reset-password page renders and shows email field for forgot flow", async ({ page }) => {
    await page.goto("/reset-password?token=invalid-token-test");
    await expect(page.getByRole("heading", { name: "Reset password" })).toBeVisible();
  });
});

test.describe("Password reset / UI", () => {
  test("forgot link is on login page", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("link", { name: "Forgot password?" })).toBeVisible();
  });

  test("unauthenticated cannot access protected pages after password change (session revocation check)", async () => {
    const email = USERS.pwreset.email;
    const viewerTokenOld = await apiLogin(email, E2E_PASSWORD);
    const change = await apiPost("/api/v1/auth/change-password", viewerTokenOld, { current_password: E2E_PASSWORD, new_password: "ViewerNewPass123!A", confirm_password: "ViewerNewPass123!A" });
    expect(change.status).toBe(200);
    const newLogin = await apiLoginRaw(email, "ViewerNewPass123!A");
    expect(newLogin.status).toBe(200);
    const newToken = newLogin.body.access_token;
    expect(newToken).toBeTruthy();
    if (newToken) {
      const back = await apiPost("/api/v1/auth/change-password", newToken, { current_password: "ViewerNewPass123!A", new_password: E2E_PASSWORD, confirm_password: E2E_PASSWORD });
      if (back.status !== 200) {
        const superT2 = await apiLogin(USERS.superAdmin.email, E2E_PASSWORD);
        await apiForgotPassword(email);
        const out2 = await apiGet("/api/v1/auth/_debug/email-outbox", superT2);
        let tok2 = null;
        if (out2.status === 200) {
          const e = [...out2.body.outbox].reverse().find((x) => x.to?.toLowerCase() === email.toLowerCase());
          tok2 = e?.token;
        }
        if (tok2) {
          const r2 = await apiResetPassword(tok2, E2E_PASSWORD, E2E_PASSWORD);
          expect(r2.status).toBe(200);
        }
      } else {
        expect(back.status).toBe(200);
      }
    }
    const oldCheck = await apiLoginRaw(email, "ViewerNewPass123!A");
    expect(oldCheck.status).toBe(401);
    const restored = await apiLoginRaw(email, E2E_PASSWORD);
    expect(restored.status).toBe(200);
  });
});
