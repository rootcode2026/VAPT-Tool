import { api } from "./client";

export function getProjectComplianceSummary(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/compliance/summary`, { query });
}

export function listProjectComplianceControls(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/compliance/controls`, { query });
}

export function getProjectComplianceControl(projectId, controlId) {
  return api.get(`/api/v1/projects/${projectId}/compliance/controls/${controlId}`);
}

export function listProjectComplianceEvidence(projectId, controlId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/compliance/controls/${controlId}/evidence`, { query });
}
