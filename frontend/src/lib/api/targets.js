import { api } from "./client";

export function listTargets() {
  return api.get("/api/v1/targets");
}

export function createTarget(payload) {
  return api.post("/api/v1/targets", payload);
}

export function deleteTarget(targetId) {
  return api.delete(`/api/v1/targets/${targetId}`);
}
