import { api } from "./client";

export function getAIStatus() {
  return api.get("/api/v1/ai/status");
}
export function listConversations(projectId) {
  return api.get("/api/v1/ai/conversations", { query: { project_id: projectId } });
}
export function createConversation(projectId, title) {
  return api.post("/api/v1/ai/conversations", { project_id: projectId, title });
}
export function getConversation(id) {
  return api.get(`/api/v1/ai/conversations/${id}`);
}
export function postMessage(conversationId, content) {
  return api.post(`/api/v1/ai/conversations/${conversationId}/messages`, { content });
}
export function deleteConversation(id) {
  return api.delete(`/api/v1/ai/conversations/${id}`);
}
export function queryAI(projectId, prompt, filters = {}) {
  return api.post("/api/v1/ai/query", { project_id: projectId, prompt, filters });
}
export function explainFinding(findingId, projectId) {
  return api.post(`/api/v1/ai/findings/${findingId}/explain`, { project_id: projectId });
}
export function investigateAsset(assetId, projectId) {
  return api.post(`/api/v1/ai/assets/${assetId}/investigate`, { project_id: projectId });
}
export function investigateProject(projectId, question) {
  return api.post("/api/v1/ai/investigate", { project_id: projectId, question });
}
export function explainAttackPath(attackPathId, projectId) {
  return api.post(`/api/v1/ai/attack-paths/${attackPathId}/explain`, { project_id: projectId });
}
export function explainMonitoring(projectId, runId) {
  return api.post("/api/v1/ai/monitoring/explain", { project_id: projectId, run_id: runId });
}
export function recommendRemediation(projectId, findingId) {
  return api.post("/api/v1/ai/remediation/recommend", { project_id: projectId, finding_id: findingId });
}
export function explainRetest(findingId, projectId) {
  return api.post(`/api/v1/ai/retest/${findingId}/explain`, { project_id: projectId });
}
export function draftReport(projectId, reportType, periodDays) {
  return api.post("/api/v1/ai/reports/draft", { project_id: projectId, report_type: reportType, period_days: periodDays });
}
