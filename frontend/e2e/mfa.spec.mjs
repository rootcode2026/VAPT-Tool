/**
 * MFA — TOTP enrollment, challenge, recovery codes, enforcement, and UI.
 */
import { test, expect } from "@playwright/test";
import {
  USERS,
  STATE_FILES,
  asUser,
  apiGet,
  apiPost,
  apiPatch,
  apiLogin,
  apiLoginRaw,
  apiMfaSetup,
  apiMfaSetupVerify,
  apiMfaDisable,
  apiMfaRegenerate,
  apiMfaStatus,
  apiMfaChallenge,
  totpNow,
} from "./support/helpers.mjs";

async function debugReset(email, token) {
  const res = await apiPost("/api/v1/auth/_debug/mfa/reset", token, { email });
  return res;
}

test.describe("MFA / enrollment (memberB isolated)", () => {
  let memberBToken = null;

  test.beforeAll(async () => {
    const adminToken = await apiLogin(USERS.superAdmin.email, USERS.superAdmin.password);
    await debugReset(USERS.memberB.email, adminToken);
    await debugReset(USERS.projectAdmin.email, adminToken);
    await debugReset(USERS.viewer.email, adminToken);
    await debugReset(USERS.orgAdmin.email, adminToken);
  });

  test("MFA status is initially disabled", async () => {
    const token = await apiLogin(USERS.memberB.email, USERS.memberB.password);
    const res = await apiMfaStatus(token);
    expect(res.status).toBe(200);
    expect(res.body.mfa_enabled).toBe(false);
    expect(res.body.mfa_required).toBe(false);
    expect(res.body.recovery_codes_remaining).toBeNull();
    expect(JSON.stringify(res.body).toLowerCase()).not.toContain("secret");
  });

  test("setup generates a secret and otpauth URI", async () => {
    const token = await apiLogin(USERS.memberB.email, USERS.memberB.password);
    const setup = await apiMfaSetup(token);
    expect(setup.status).toBe(200);
    expect(setup.body.secret).toMatch(/^[A-Z2-7]+$/);
    expect(setup.body.otpauth_uri).toContain("otpauth://totp/");
    expect(decodeURIComponent(setup.body.otpauth_uri)).toContain(USERS.memberB.email);
    expect(setup.body).not.toHaveProperty("password");
  });

  test("verification with invalid code fails", async () => {
    const token = await apiLogin(USERS.memberB.email, USERS.memberB.password);
    await apiMfaSetup(token);
    const res = await apiMfaSetupVerify(token, "000000");
    expect(res.status).toBe(400);
  });

  test("verification with valid TOTP enables MFA and returns recovery codes", async () => {
    const token = await apiLogin(USERS.memberB.email, USERS.memberB.password);
    const setup = await apiMfaSetup(token);
    expect(setup.status).toBe(200);
    const secret = setup.body.secret;
    const code = totpNow(secret);
    const res = await apiMfaSetupVerify(token, code);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.recovery_codes)).toBe(true);
    expect(res.body.recovery_codes.length).toBe(10);
    for (const c of res.body.recovery_codes) expect(c).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    const st = await apiMfaStatus(token);
    expect(st.body.mfa_enabled).toBe(true);
    expect(st.body.recovery_codes_remaining).toBe(10);
    memberBToken = token;
  });

  test("login now requires MFA challenge", async () => {
    const raw = await apiLoginRaw(USERS.memberB.email, USERS.memberB.password);
    expect(raw.status).toBe(200);
    expect(raw.body.mfa_required).toBe(true);
    expect(raw.body.mfa_token).toBeTruthy();
    const bad = await apiMfaChallenge(raw.body.mfa_token, "000000");
    expect(bad.status).toBe(401);
  });

  test("recovery code is single-use and regeneration invalidates old codes", async () => {
    // Use a fresh user viewer for this lifecycle to avoid memberB state pollution
    const adminToken = await apiLogin(USERS.superAdmin.email, USERS.superAdmin.password);
    await debugReset(USERS.viewer.email, adminToken);
    const vToken = await apiLogin(USERS.viewer.email, USERS.viewer.password);
    const setup = await apiMfaSetup(vToken);
    expect(setup.status).toBe(200);
    const code = totpNow(setup.body.secret);
    const vr = await apiMfaSetupVerify(vToken, code);
    expect(vr.status).toBe(200);
    const codes = vr.body.recovery_codes;
    const first = codes[0];
    // Use recovery code for challenge
    const raw = await apiLoginRaw(USERS.viewer.email, USERS.viewer.password);
    const chal1 = await apiMfaChallenge(raw.body.mfa_token, first);
    expect(chal1.status).toBe(200);
    // Reuse should fail
    const raw2 = await apiLoginRaw(USERS.viewer.email, USERS.viewer.password);
    const chal2 = await apiMfaChallenge(raw2.body.mfa_token, first);
    expect(chal2.status).toBe(401);
    // Regeneration
    const authed = chal1.body.access_token;
    const newTotp = totpNow(setup.body.secret);
    const regen = await apiMfaRegenerate(authed, USERS.viewer.password, newTotp);
    expect(regen.status).toBe(200);
    expect(regen.body.recovery_codes.length).toBe(10);
    expect(regen.body.recovery_codes).not.toContain(first);
    // Cleanup
    const dis = await apiMfaDisable(authed, USERS.viewer.password, totpNow(setup.body.secret));
    expect(dis.status).toBe(200);
  });

  test("MFA disable requires password and valid code", async () => {
    // memberB is currently enabled from earlier test
    const loginRaw = await apiLoginRaw(USERS.memberB.email, USERS.memberB.password);
    expect(loginRaw.body.mfa_required).toBe(true);
    // Need to get an authenticated token via MFA challenge using TOTP — but we lost secret.
    // Instead we will reset memberB via debug and re-enable with known secret for this test
    const adminToken = await apiLogin(USERS.superAdmin.email, USERS.superAdmin.password);
    await debugReset(USERS.memberB.email, adminToken);
    const token = await apiLogin(USERS.memberB.email, USERS.memberB.password);
    const setup = await apiMfaSetup(token);
    const code = totpNow(setup.body.secret);
    const vr = await apiMfaSetupVerify(token, code);
    expect(vr.status).toBe(200);
    const badPass = await apiMfaDisable(token, "wrongpass", code);
    expect(badPass.status).toBe(401);
    const good = await apiMfaDisable(token, USERS.memberB.password, code);
    expect(good.status).toBe(200);
    const st = await apiMfaStatus(token);
    expect(st.body.mfa_enabled).toBe(false);
  });

  test("super-admin MFA is marked required", async () => {
    const token = await apiLogin(USERS.superAdmin.email, USERS.superAdmin.password);
    const res = await apiMfaStatus(token);
    expect(res.status).toBe(200);
    expect(res.body.mfa_required).toBe(true);
  });

  test("unauthenticated cannot manage MFA", async () => {
    const r1 = await apiMfaSetup(null);
    expect([401, 403].includes(r1.status)).toBe(true);
  });

  test("viewer cannot manage organization MFA policy", async () => {
    const vToken = await apiLogin(USERS.viewer.email, USERS.viewer.password);
    const patch = await apiPatch(`/api/v1/organizations/${"e2eaaaaa-0000-4000-8000-000000000001"}/security/mfa`, vToken, { mfa_required: true });
    // Viewer is member, not org_admin — must be denied.
    expect([401, 403, 404, 429].includes(patch.status)).toBe(true);
    if (patch.status === 200) {
      throw new Error(`Viewer was able to set MFA policy: ${JSON.stringify(patch.body)}`);
    }
  });

  test("no secret leakage in MFA status", async () => {
    const token = await apiLogin(USERS.analyst.email, USERS.analyst.password);
    const st = await apiMfaStatus(token);
    const bodyStr = JSON.stringify(st.body);
    expect(bodyStr.toLowerCase()).not.toContain("secret");
    expect(bodyStr.toLowerCase()).not.toContain("otpauth");
  });

  test.afterAll(async () => {
    const adminToken = await apiLogin(USERS.superAdmin.email, USERS.superAdmin.password);
    await debugReset(USERS.memberB.email, adminToken);
    await debugReset(USERS.viewer.email, adminToken);
    await debugReset(USERS.projectAdmin.email, adminToken);
    await debugReset(USERS.orgAdmin.email, adminToken);
  });
});

test.describe("MFA / UI — settings", () => {
  test.use({ storageState: STATE_FILES.analyst });

  test("security settings page shows MFA status and enable flow", async ({ page }) => {
    await asUser(page, "analyst");
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Multi-factor authentication" })).toBeVisible();
    await expect(page.getByText(/Status:/)).toBeVisible();
    const enableBtn = page.getByRole("button", { name: "Enable MFA" });
    if (await enableBtn.isVisible()) {
      await enableBtn.click();
      await expect(page.getByText(/Scan this QR code/)).toBeVisible();
    }
  });
});

test.describe("MFA / UI — login challenge", () => {
  test("login shows MFA challenge when required", async ({ page }) => {
    // Enable MFA for memberB, then login via UI should show MFA challenge
    const adminToken = await apiLogin(USERS.superAdmin.email, USERS.superAdmin.password);
    await debugReset(USERS.memberB.email, adminToken);
    let token = await apiLogin(USERS.memberB.email, USERS.memberB.password);
    const setup = await apiMfaSetup(token);
    const code = totpNow(setup.body.secret);
    await apiMfaSetupVerify(token, code);
    await page.goto("/login");
    await page.locator("#email").fill(USERS.memberB.email);
    await page.locator("#password").fill(USERS.memberB.password);
    await page.getByRole("button", { name: "Sign In" }).click();
    await expect(page.getByText("Two-factor authentication")).toBeVisible();
    await expect(page.locator("#mfa-code")).toBeVisible();
    // Cleanup
    const raw = await apiLoginRaw(USERS.memberB.email, USERS.memberB.password);
    const chal = await apiMfaChallenge(raw.body.mfa_token, totpNow(setup.body.secret));
    const authed = chal.body.access_token;
    await apiMfaDisable(authed, USERS.memberB.password, totpNow(setup.body.secret));
  });
});
