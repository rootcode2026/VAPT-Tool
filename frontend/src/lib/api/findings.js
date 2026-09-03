import { api } from "./client";

export function listFindings(query) {
  return api.get("/api/v1/findings", { query });
}

export function getFinding(findingId) {
  return api.get(`/api/v1/findings/${findingId}`);
}
