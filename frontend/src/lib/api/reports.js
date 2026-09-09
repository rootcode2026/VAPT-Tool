import { API_BASE_URL, api, apiFetch } from "./client";

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
export async function downloadReport(id, format) {
  const response = await apiFetch(`${API_BASE_URL}/api/v1/reports/${id}/download/${format}`);
  if (!response.ok) {
    let message = `Download failed (${response.status})`;
    try {
      const data = await response.json();
      if (data && data.detail) message = data.detail;
    } catch {
      // fall through with default message
    }
    throw new Error(message);
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  const ext = format === "pdf" ? "pdf" : format === "csv" ? "csv" : "json";
  link.download = `report-${id}.${ext}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
  return true;
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
