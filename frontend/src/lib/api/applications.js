import { api } from "./client";

export function listApplications(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/applications`, { query: params });
}
export function createApplication(projectId, data) {
  return api.post(`/api/v1/projects/${projectId}/applications`, data);
}
export function getApplication(projectId, appId) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}`);
}
export function updateApplication(projectId, appId, data) {
  return api.patch(`/api/v1/projects/${projectId}/applications/${appId}`, data);
}
export function getApplicationSummary(projectId, appId) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/summary`);
}
export function listApplicationAssets(projectId, appId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/assets`, { query: params });
}
export function linkApplicationAsset(projectId, appId, data) {
  return api.post(`/api/v1/projects/${projectId}/applications/${appId}/assets/link`, data);
}
export function listApplicationFindings(projectId, appId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/findings`, { query: params });
}
export function listApplicationCorrelations(projectId, appId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/correlations`, { query: params });
}
export function getApplicationExposure(projectId, appId) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/exposure`);
}
export function getApplicationRisk(projectId, appId) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/risk`);
}
export function listApplicationChanges(projectId, appId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/changes`, { query: params });
}
export function createApplicationInvestigation(projectId, appId, data = {}) {
  return api.post(`/api/v1/projects/${projectId}/applications/${appId}/investigation`, data);
}
export function listApplicationInvestigations(projectId, appId) {
  return api.get(`/api/v1/projects/${projectId}/applications/${appId}/investigation`);
}
