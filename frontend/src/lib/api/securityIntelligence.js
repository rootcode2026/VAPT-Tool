import { api } from "./client";
export function getSecurityContext(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/context/${subjectType}/${subjectId}`);
}
export function getBlastRadius(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/blast-radius/${subjectType}/${subjectId}`);
}
export function getExposureChain(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/exposure-chain/${subjectType}/${subjectId}`);
}
export function getImpact(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/impact/${subjectType}/${subjectId}`);
}
export function getPriorities(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/priorities`, { query: params });
}
export function getPriority(projectId, subjectType, subjectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/priorities/${subjectType}/${subjectId}`);
}
export function getTopRisks(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/top-risks`);
}
export function getPrioritySummary(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/priority-summary`);
}
export function getTrends(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/trends`, { query: params });
}
export function getTrendsSummary(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/trends/summary`, { query: params });
}
export function getSubjectTrends(projectId, subjectType, subjectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/trends/${subjectType}/${subjectId}`, { query: params });
}
export function getAttackSurface(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface`, { query: params });
}
export function getAttackDistribution(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/distribution`);
}
export function getAttackHotspots(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/hotspots`, { query: params });
}
export function getAttackConcentration(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/concentration`);
}
export function getAttackCoverage(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/coverage`);
}
export function getAttackTechnology(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/technology`);
}
export function getAttackCloud(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/cloud`);
}
export function getAttackApplications(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/applications`);
}
export function getAttackTop(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/top`);
}
export function getAttackHistorical(projectId, window = "7d") {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-surface/historical`, { query: { window } });
}
export function getExposureChains(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/exposure-chains`, { query: params });
}
export function getExposureDecision(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/exposure-decision`);
}
export function getExposureConcentration(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/exposure-concentration`);
}
export function getChangeExposure(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/change-exposure`, { query: params });
}
export function getCoverageF5(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/coverage`);
}
export function getRootCause(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/root-cause`, { query: params });
}
export function getHistoryF6(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/history`, { query: params });
}
export function getScorecard(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/scorecard`, { query: params });
}
export function getRecurringExposure(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/recurring-exposure`, { query: params });
}
export function getRemediationEffectiveness(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/remediation-effectiveness`);
}
export function getAttackPathHistory(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/attack-path-history`, { query: params });
}
export function getSubjectHistory(projectId, subjectType, subjectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/subject-history/${subjectType}/${subjectId}`, { query: params });
}
export function getRiskAcceptanceAging(projectId) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/risk-acceptance-aging`);
}
export function getImprovement(projectId, params = {}) {
  return api.get(`/api/v1/projects/${projectId}/security-intelligence/improvement`, { query: params });
}
