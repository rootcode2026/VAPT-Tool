import { api } from "./client";

export function getAdminDashboardSummary() {
  return api.get("/api/v1/admin/dashboard/summary");
}

export function getAdminOrganizationsSummary(params = {}) {
  return api.get("/api/v1/admin/organizations/summary", { query: params });
}

export function listAdminOrganizations(params = {}) {
  return api.get("/api/v1/admin/organizations", { query: params });
}

export function createAdminOrganization(payload) {
  return api.post("/api/v1/admin/organizations", payload);
}

export function getAdminOrganization(orgId) {
  return api.get(`/api/v1/admin/organizations/${orgId}`);
}

export function updateAdminOrganization(orgId, payload) {
  return api.patch(`/api/v1/admin/organizations/${orgId}`, payload);
}

export function listAdminUsers(params = {}) {
  return api.get("/api/v1/admin/users", { query: params });
}

export function getAdminUser(userId) {
  return api.get(`/api/v1/admin/users/${userId}`);
}

export function updateAdminUser(userId, payload) {
  return api.patch(`/api/v1/admin/users/${userId}`, payload);
}

export function listScanners() {
  return api.get("/api/v1/admin/scanners");
}
export function getScanner(key) {
  return api.get(`/api/v1/admin/scanners/${key}`);
}
export function patchScanner(key, payload) {
  return api.patch(`/api/v1/admin/scanners/${key}`, payload);
}
export function listScannerVersions(key) {
  return api.get(`/api/v1/admin/scanners/${key}/versions`);
}
export function createScannerVersion(key, payload) {
  return api.post(`/api/v1/admin/scanners/${key}/versions`, payload);
}
export function getScannerHealth(key) {
  return api.get(`/api/v1/admin/scanners/${key}/health`);
}
export function triggerScannerHealthCheck(key) {
  return api.post(`/api/v1/admin/scanners/${key}/health/check`);
}
export function upgradeScanner(key, payload) {
  return api.post(`/api/v1/admin/scanners/${key}/upgrade`, payload);
}
export function downgradeScanner(key, payload) {
  return api.post(`/api/v1/admin/scanners/${key}/downgrade`, payload);
}
export function rollbackScanner(key) {
  return api.post(`/api/v1/admin/scanners/${key}/rollback`);
}
export function getFleet() {
  return api.get("/api/v1/admin/scanner-fleet");
}
export function getFleetPools() {
  return api.get("/api/v1/admin/scanner-fleet/pools");
}
export function listRollouts(params = {}) {
  return api.get("/api/v1/admin/scanner-rollouts", { query: params });
}
export function getRollout(id) {
  return api.get(`/api/v1/admin/scanner-rollouts/${id}`);
}
