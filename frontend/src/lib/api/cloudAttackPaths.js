import { api } from "./client";

export function listCloudAttackPaths(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/attack-paths`, { query: params });
}
export function getCloudAttackPath(projectId, pathId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/attack-paths/${pathId}`);
}
