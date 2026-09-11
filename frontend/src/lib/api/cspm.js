import { api } from "./client";

export function getCspmSummary(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cspm`, { query: params });
}
export function listCspmControls(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cspm/controls`, { query: params });
}
export function getCspmControl(projectId, controlId) {
  return api.get(`/api/v1/projects/${projectId}/cspm/controls/${controlId}`);
}
