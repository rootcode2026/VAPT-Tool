import { api } from "./client";

export function getExternalAttackSurface(projectId) {
  return api.get(`/api/v1/projects/${projectId}/external-attack-surface`);
}
export function getEASSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/external-attack-surface/summary`);
}
export function listEASAssets(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/external-attack-surface/assets`, { query: params });
}
export function getEASAsset(projectId, assetId) {
  return api.get(`/api/v1/projects/${projectId}/external-attack-surface/assets/${assetId}`);
}
export function listEASCandidates(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/external-attack-surface/candidates`, { query: params });
}
export function confirmEASAsset(projectId, assetId) {
  return api.post(`/api/v1/projects/${projectId}/external-attack-surface/candidates/${assetId}/confirm`);
}
export function rejectEASAsset(projectId, assetId) {
  return api.post(`/api/v1/projects/${projectId}/external-attack-surface/candidates/${assetId}/reject`);
}
export function listEASScopes(projectId) {
  return api.get(`/api/v1/projects/${projectId}/external-attack-surface/scopes`);
}
export function createEASScope(projectId, data) {
  return api.post(`/api/v1/projects/${projectId}/external-attack-surface/scopes`, data);
}
export function createEASScopeEntry(projectId, scopeId, data) {
  return api.post(`/api/v1/projects/${projectId}/external-attack-surface/scopes/${scopeId}/entries`, data);
}
export function discoverEAS(projectId, data) {
  return api.post(`/api/v1/projects/${projectId}/external-attack-surface/discover`, data);
}
export function listEASRuns(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/external-attack-surface/runs`, { query: params });
}
