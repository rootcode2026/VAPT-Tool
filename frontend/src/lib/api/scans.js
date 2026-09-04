import { api } from "./client";

export function listScans(query) {
  return api.get("/api/v1/scans", { query });
}

export function listProjectScans(projectId, query = {}) {
  return api.get(`/api/v1/projects/${projectId}/scans`, { query });
}

export function getScan(scanId) {
  return api.get(`/api/v1/scans/${scanId}`);
}

export function getScanDetails(scanId) {
  return api.get(`/api/v1/scans/${scanId}/details`);
}

export function getScanProgress(scanId) {
  return api.get(`/api/v1/scans/${scanId}/progress`);
}

export function createScan(payload) {
  return api.post("/api/v1/scans", payload);
}
