import { api } from "./client";

export function listAssets(query) {
  return api.get("/api/v1/assets", { query });
}

export function getAsset(assetId) {
  return api.get(`/api/v1/assets/${assetId}`);
}

export function getAssetRelationships(assetId) {
  return api.get(`/api/v1/assets/${assetId}/relationships`);
}

export function listAssetRelationships(query) {
  return api.get("/api/v1/assets/relationships", { query });
}

export function getAttackPaths(query) {
  return api.get("/api/v1/assets/attack-paths", { query });
}

export function getProjectAttackPaths(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/attack-paths`, { query });
}

export function getProjectSecuritySummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-summary`);
}

export function getProjectRiskSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/risk-summary`);
}

export function listProjectAssets(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/assets`, { query });
}
