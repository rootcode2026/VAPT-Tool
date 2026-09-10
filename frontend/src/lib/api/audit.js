import { API_BASE_URL, api, apiFetch } from "./client";

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

function cleanQuery(params, keys) {
  const query = {};
  for (const k of keys) {
    const v = params[k];
    if (v !== undefined && v !== null && String(v).trim() !== "") {
      query[k] = String(v).trim();
    }
  }
  return query;
}

const PROJECT_AUDIT_KEYS = [
  "event_type",
  "action",
  "result",
  "resource_type",
  "resource_id",
  "actor_user_id",
  "correlation_id",
  "since",
  "until",
  "limit",
  "offset",
];

export function listProjectAudit(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/audit`, { query: cleanQuery(params, PROJECT_AUDIT_KEYS) });
}

export function getProjectAuditRecord(projectId, auditId) {
  return api.get(`/api/v1/projects/${projectId}/audit/${auditId}`);
}

export async function exportProjectAudit(projectId, params = {}) {
  const query = cleanQuery(params, ["format", "event_type", "result", "actor_user_id", "since", "until"]);
  const qs = new URLSearchParams(query).toString();
  const response = await apiFetch(`${API_BASE_URL}/api/v1/projects/${projectId}/audit/export${qs ? `?${qs}` : ""}`);
  if (!response.ok) {
    let message = `Export failed (${response.status})`;
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
  const fmt = (params.format || "json").toLowerCase() === "csv" ? "csv" : "json";
  link.download = `audit-${projectId}.${fmt}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
  return true;
}

export function verifyProjectAudit(projectId, payload = {}) {
  return api.post(`/api/v1/projects/${projectId}/audit/verify-integrity`, payload);
}
