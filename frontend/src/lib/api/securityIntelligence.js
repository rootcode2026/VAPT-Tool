import { api } from "./client";
export function getSecurityContext(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/context/${subjectType}/${subjectId}`);
}
export function getBlastRadius(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/blast-radius/${subjectType}/${subjectId}`);
}
export function getExposureChain(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/exposure-chain/${subjectType}/${subjectId}`);
}
export function getImpact(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/impact/${subjectType}/${subjectId}`);
}
export function getPriorities(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/priorities`, { query: params });
}
export function getPriority(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/priorities/${subjectType}/${subjectId}`);
}
export function getTopRisks(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/top-risks`);
}
export function getPrioritySummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/priority-summary`);
}
