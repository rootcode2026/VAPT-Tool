import { api } from "./client";

export function listFindings(query) {
  return api.get("/api/v1/findings", { query });
}

export function getFinding(findingId) {
  return api.get(`/api/v1/findings/${findingId}`);
}

export function updateFinding(findingId, payload) {
  return api.patch(`/api/v1/findings/${findingId}`, payload);
}

export function listFindingComments(findingId, query = {}) {
  return api.get(`/api/v1/findings/${findingId}/comments`, { query });
}

export function createFindingComment(findingId, body) {
  return api.post(`/api/v1/findings/${findingId}/comments`, { body });
}

export function listFindingHistory(findingId, query = {}) {
  return api.get(`/api/v1/findings/${findingId}/history`, { query });
}

export function listProjectFindings(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/findings`, { query });
}

export function getFindingSLA(findingId) {
  return api.get(`/api/v1/findings/${findingId}/sla`);
}

export function startFindingSLA(findingId) {
  return api.post(`/api/v1/findings/${findingId}/sla/start`);
}

export function updateFindingSLA(findingId, payload) {
  return api.patch(`/api/v1/findings/${findingId}/sla`, payload);
}

export function listRiskAcceptances(findingId) {
  return api.get(`/api/v1/findings/${findingId}/risk-acceptances`);
}

export function requestRiskAcceptance(findingId, payload) {
  return api.post(`/api/v1/findings/${findingId}/risk-acceptances/request`, payload);
}

export function reviewRiskAcceptance(findingId, raId, payload) {
  return api.patch(`/api/v1/findings/${findingId}/risk-acceptances/${raId}`, payload);
}

export function listRemediations(findingId) {
  return api.get(`/api/v1/findings/${findingId}/remediations`);
}

export function createRemediation(findingId, payload) {
  return api.post(`/api/v1/findings/${findingId}/remediations`, payload);
}

export function updateRemediation(findingId, remId, payload) {
  return api.patch(`/api/v1/findings/${findingId}/remediations/${remId}`, payload);
}

export function listRetests(findingId) {
  return api.get(`/api/v1/findings/${findingId}/retests`);
}

export function requestRetest(findingId) {
  return api.post(`/api/v1/findings/${findingId}/retests/request`);
}

export function updateRetest(findingId, retestId, payload) {
  return api.patch(`/api/v1/findings/${findingId}/retests/${retestId}`, payload);
}

export function listProjectRemediations(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/remediations`, { query });
}

export function getProjectRemediation(projectId, remediationId) {
  return api.get(`/api/v1/projects/${projectId}/remediations/${remediationId}`);
}

export function startProjectRemediation(projectId, remediationId) {
  return api.post(`/api/v1/projects/${projectId}/remediations/${remediationId}/start`);
}

export function blockProjectRemediation(projectId, remediationId, payload) {
  return api.post(`/api/v1/projects/${projectId}/remediations/${remediationId}/block`, payload);
}

export function unblockProjectRemediation(projectId, remediationId) {
  return api.post(`/api/v1/projects/${projectId}/remediations/${remediationId}/unblock`);
}

export function completeProjectRemediation(projectId, remediationId, payload = {}) {
  return api.post(`/api/v1/projects/${projectId}/remediations/${remediationId}/complete`, payload);
}

export function getProjectSLASummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/sla/summary`);
}

export function getOrgSLAPolicy(organizationId) {
  return api.get(`/api/v1/organizations/${organizationId}/sla-policy`);
}

export function updateOrgSLAPolicy(organizationId, policy) {
  return api.put(`/api/v1/organizations/${organizationId}/sla-policy`, { policy });
}
