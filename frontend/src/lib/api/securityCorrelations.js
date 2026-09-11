import { api } from "./client";

export function listSecurityCorrelations(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security/correlations`, { query: params });
}
export function getSecurityCorrelation(projectId, correlationId) {
  return api.get(`/api/v1/projects/${projectId}/security/correlations/${correlationId}`);
}
export function getSecurityCorrelationSummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security/correlations/summary`);
}
