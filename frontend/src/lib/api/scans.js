import { api } from "./client";

export function listScans(query) {
  return api.get("/api/v1/scans", { query });
}

export function getScan(scanId) {
  return api.get(`/api/v1/scans/${scanId}`);
}

export function getScanDetails(scanId) {
  return api.get(`/api/v1/scans/${scanId}/details`);
}

export function createScan(payload) {
  return api.post("/api/v1/scans", payload);
}
