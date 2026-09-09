import { api } from "./client";

export function listAlerts(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/alerts`, { query });
}

export function getAlert(projectId, alertId) {
  return api.get(`/api/v1/projects/${projectId}/alerts/${alertId}`);
}

export function acknowledgeAlert(projectId, alertId) {
  return api.post(`/api/v1/projects/${projectId}/alerts/${alertId}/acknowledge`);
}

export function resolveAlert(projectId, alertId) {
  return api.post(`/api/v1/projects/${projectId}/alerts/${alertId}/resolve`);
}

export function getAlertPolicy(projectId) {
  return api.get(`/api/v1/projects/${projectId}/alert-policy`);
}

export function updateAlertPolicy(projectId, policy) {
  return api.put(`/api/v1/projects/${projectId}/alert-policy`, policy);
}
