import { api } from "./client";

export function getProjectDashboardSummary(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/dashboard/summary`, { query });
}
