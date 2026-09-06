import { api } from "./client";

export function createDastConfig(projectId, payload) {
  return api.post(`/api/v1/projects/${projectId}/dast/config`, payload);
}
export function getDastConfig(projectId) {
  return api.get(`/api/v1/projects/${projectId}/dast/config`);
}
export function updateDastConfig(projectId, configId, payload) {
  return api.patch(`/api/v1/projects/${projectId}/dast/config/${configId}`, payload);
}
export function createDastScan(projectId, payload) {
  return api.post(`/api/v1/projects/${projectId}/dast/scans`, payload);
}
export function listDastScans(projectId) {
  return api.get(`/api/v1/projects/${projectId}/dast/scans`);
}
export function listDastEndpoints(projectId) {
  return api.get(`/api/v1/projects/${projectId}/dast/endpoints`);
}
export function listDastParameters(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/dast/parameters`, { query: params });
}
export function validateApiSecurity(projectId, payload) {
  return api.post(`/api/v1/projects/${projectId}/api-security/validate`, payload);
}
export function getApiSecuritySummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/api-security/summary`);
}
