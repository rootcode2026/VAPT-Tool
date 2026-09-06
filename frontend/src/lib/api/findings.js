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
