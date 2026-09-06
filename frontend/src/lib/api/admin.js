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
