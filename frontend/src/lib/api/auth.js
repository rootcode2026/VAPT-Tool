import { api } from "./client";

export function login(email, password) {
  return api.post(
    "/api/v1/auth/login",
    { email, password },
    { auth: false, authRedirect: false }
  );
}

export function mfaChallenge(mfaToken, code) {
  return api.post(
    "/api/v1/auth/mfa/challenge",
    { mfa_token: mfaToken, code },
    { auth: false, authRedirect: false }
  );
}

export function getCurrentUser() {
  return api.get("/api/v1/auth/me", { authRedirect: false });
}

export function logout() {
  return api.post("/api/v1/auth/logout", undefined, { authRedirect: false });
}

export function getMfaStatus() {
  return api.get("/api/v1/auth/mfa/status");
}

export function mfaSetup() {
  return api.post("/api/v1/auth/mfa/setup");
}

export function mfaSetupVerify(code) {
  return api.post("/api/v1/auth/mfa/setup/verify", { code });
}

export function mfaDisable(password, code) {
  return api.post("/api/v1/auth/mfa/disable", { password, code });
}

export function mfaRegenerate(password, code) {
  return api.post("/api/v1/auth/mfa/recovery-codes/regenerate", { password, code });
}

export function forgotPassword(email) {
  return api.post("/api/v1/auth/forgot-password", { email }, { auth: false, authRedirect: false });
}

export function resetPassword(token, new_password, confirm_password) {
  return api.post("/api/v1/auth/reset-password", { token, new_password, confirm_password }, { auth: false, authRedirect: false });
}

export function changePassword(current_password, new_password, confirm_password) {
  return api.post("/api/v1/auth/change-password", { current_password, new_password, confirm_password });
}

export function getOrgMfaPolicy(organizationId) {
  return api.get(`/api/v1/organizations/${organizationId}/security/mfa`);
}

export function setOrgMfaPolicy(organizationId, mfa_required) {
  return api.patch(`/api/v1/organizations/${organizationId}/security/mfa`, { mfa_required });
}
