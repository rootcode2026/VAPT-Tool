import { api } from "./client";

export function listNotifications(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/notifications`, { query });
}

export function markNotificationRead(projectId, notificationId) {
  return api.post(`/api/v1/projects/${projectId}/notifications/${notificationId}/read`);
}

export function getNotificationPolicy(projectId) {
  return api.get(`/api/v1/projects/${projectId}/notification-policies`);
}

export function updateNotificationPolicy(projectId, policy) {
  return api.put(`/api/v1/projects/${projectId}/notification-policies`, policy);
}

export function listNotificationDeliveries(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/notification-deliveries`, { query });
}

export function notifyAlert(projectId, alertId) {
  return api.post(`/api/v1/projects/${projectId}/alerts/${alertId}/notify`);
}
