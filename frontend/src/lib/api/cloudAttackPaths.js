import { api } from "./client";

export function listCloudAttackPaths(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/attack-paths`, { query: params });
}
export function getCloudAttackPath(projectId, pathId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/attack-paths/${pathId}`);
}
export function listAttackPathHistory(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/attack-paths/history`, { query: params });
}
export function getAttackPathHistory(projectId, pathId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/attack-paths/history/${pathId}`);
}
export function getAttackPathSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/attack-paths/summary`);
}
export function observeAttackPaths(projectId, params = {}) {
  return api.post(`/api/v1/projects/${projectId}/cloud-security/attack-paths/observe`, null, { query: params });
}
