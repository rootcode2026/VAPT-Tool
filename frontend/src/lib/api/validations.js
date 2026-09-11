import { api } from "./client";

export function listValidations(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security/validations`, { query: params });
}
export function getValidation(projectId, validationId) {
  return api.get(`/api/v1/projects/${projectId}/security/validations/${validationId}`);
}
export function createValidation(projectId, data) {
  return api.post(`/api/v1/projects/${projectId}/security/validations`, data);
}
export function validateFinding(projectId, findingId, data = {}) {
  return api.post(`/api/v1/projects/${projectId}/findings/${findingId}/validate`, data);
}
export function listFindingValidations(projectId, findingId) {
  return api.get(`/api/v1/projects/${projectId}/findings/${findingId}/validations`);
}
