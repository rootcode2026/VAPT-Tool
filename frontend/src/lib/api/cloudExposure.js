import { api } from "./client";

export function getExposureIntelligence(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/exposure-intelligence`);
}
export function listTopExposures(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/exposure-intelligence/top`, { query: params });
}
export function getExposureDetail(projectId, exposureId) {
  return api.get(`/api/v1/projects/${projectId}/cloud-security/exposure-intelligence/${exposureId}`);
}
