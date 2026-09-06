import { api } from "./client";

export function listRepoConnections(projectId) {
  return api.get(`/api/v1/projects/${projectId}/repositories/connections`);
}
export function createRepoConnection(projectId, payload) {
  return api.post(`/api/v1/projects/${projectId}/repositories/connections`, payload);
}
export function validateRepoConnection(projectId, id) {
  return api.post(`/api/v1/projects/${projectId}/repositories/connections/${id}/validate`);
}
export function syncRepoConnection(projectId, id, payload) {
  return api.post(`/api/v1/projects/${projectId}/repositories/connections/${id}/sync`, payload);
}

export function listCloudConnections(projectId) {
  return api.get(`/api/v1/projects/${projectId}/cloud/connections`);
}
export function createCloudConnection(projectId, payload) {
  return api.post(`/api/v1/projects/${projectId}/cloud/connections`, payload);
}
export function validateCloudConnection(projectId, id) {
  return api.post(`/api/v1/projects/${projectId}/cloud/connections/${id}/validate`);
}
export function discoverCloudResources(projectId, id) {
  return api.post(`/api/v1/projects/${projectId}/cloud/connections/${id}/discover`);
}
