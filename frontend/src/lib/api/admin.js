import { api } from "./client";

export function getAdminDashboardSummary() {
  return api.get("/api/v1/admin/dashboard/summary");
}

export function getAdminOrganizationsSummary(params = {}) {
  return api.get("/api/v1/admin/organizations/summary", { query: params });
}
