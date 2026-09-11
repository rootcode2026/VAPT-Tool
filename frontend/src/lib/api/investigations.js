import { api } from "./client";

export function listInvestigations(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security/investigations`, { query: params });
}
export function getInvestigation(projectId, investigationId) {
  return api.get(`/api/v1/projects/${projectId}/security/investigations/${investigationId}`);
}
export function createInvestigation(projectId, data) {
  return api.post(`/api/v1/projects/${projectId}/security/investigations`, data);
}
export function updateInvestigation(projectId, investigationId, data) {
  return api.patch(`/api/v1/projects/${projectId}/security/investigations/${investigationId}`, data);
}
export function addInvestigationNote(projectId, investigationId, data) {
  return api.post(`/api/v1/projects/${projectId}/security/investigations/${investigationId}/notes`, data);
}
export function getInvestigationTimeline(projectId, investigationId) {
  return api.get(`/api/v1/projects/${projectId}/security/investigations/${investigationId}/timeline`);
}
export function getInvestigationsSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security/investigations/summary`);
}
