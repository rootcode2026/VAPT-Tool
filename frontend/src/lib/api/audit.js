import { api } from "./client";

export function listAuditLogs(params = {}) {
  const query = {};
  // Only send defined, non-empty values; backend validates and bounds
  const keys = [
    "project_id",
    "event_type",
    "action",
    "result",
    "resource_type",
    "resource_id",
    "actor_user_id",
    "target_user_id",
    "start_time",
    "end_time",
    "page",
    "page_size",
  ];
  for (const k of keys) {
    const v = params[k];
    if (v !== undefined && v !== null && String(v).trim() !== "") {
      query[k] = String(v).trim();
    }
  }
  return api.get("/api/v1/audit_logs", { query });
}
