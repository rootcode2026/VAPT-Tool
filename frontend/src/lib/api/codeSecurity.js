import { api } from "./client";

export function getCodeSecuritySummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/code-security/summary`);
}
export function listCodeFindings(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/code-security/findings`, { query: params });
}
export function listCodeTargets(projectId) {
  return api.get(`/api/v1/projects/${projectId}/code-security/targets`);
}
export function listCodeAssets(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/code-security/assets`, { query: params });
}
export function getCloudSecuritySummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/summary`);
}
export function listCloudAccounts(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/accounts`, { query: params });
}
export function listCloudResources(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/resources`, { query: params });
}
export function listCloudFindings(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/findings`, { query: params });
}
export function listCloudChecks(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/checks`, { query: params });
}
export function getNetworkSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/network`);
}
export function getStorageSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/storage`);
}
export function getGcpSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/gcp`);
}
export function getAzureSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/azure`);
}
