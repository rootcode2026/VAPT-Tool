import { api } from "./client";

export function createReport(payload) {
  return api.post("/api/v1/reports", payload);
}
export function listReports(params = {}) {
  return api.get("/api/v1/reports", { query: params });
}
export function getReport(id) {
  return api.get(`/api/v1/reports/${id}`);
}
export function cancelReport(id) {
  return api.post(`/api/v1/reports/${id}/cancel`);
}
export function downloadReport(id, format) {
  return api.get(`/api/v1/reports/${id}/download/${format}`, { raw: true });
}
export function listFrameworks() {
  return api.get("/api/v1/compliance/frameworks");
}
export function getFramework(id) {
  return api.get(`/api/v1/compliance/frameworks/${id}`);
}
export function listControls(frameworkId, params = {}) {
  return api.get(`/api/v1/compliance/frameworks/${frameworkId}/controls`, { query: params });
}
