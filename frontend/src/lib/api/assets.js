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

export function updateAsset(assetId, payload) {
  return api.patch(`/api/v1/assets/${assetId}`, payload);
}

export function getAttackSurfaceSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/attack-surface/summary`);
}

export function listAttackSurfaceAssets(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/attack-surface/assets`, { query });
}

export function listAttackSurfaceChanges(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/attack-surface/changes`, { query });
}

export function listAttackSurfaceRelationships(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/attack-surface/relationships`, { query });
}

export function getAttackSurfaceGraph(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/attack-surface/graph`, { query });
}

export function listMonitoringConfigs(projectId) {
  return api.get(`/api/v1/projects/${projectId}/monitoring`);
}

export function createMonitoringConfig(projectId, payload) {
  return api.post(`/api/v1/projects/${projectId}/monitoring`, payload);
}

export function updateMonitoringConfig(configId, payload) {
  return api.patch(`/api/v1/monitoring/${configId}`, payload);
}

export function deleteMonitoringConfig(configId) {
  return api.delete(`/api/v1/monitoring/${configId}`);
}

export function listMonitoringRuns(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/monitoring/runs`, { query });
}

export function runMonitoringConfig(configId) {
  return api.post(`/api/v1/monitoring/${configId}/run`);
}
