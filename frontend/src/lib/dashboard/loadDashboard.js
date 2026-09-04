import { getProjectAttackPaths, getProjectSecuritySummary, listProjectAssets } from "@/lib/api/assets";
import { listProjectFindings } from "@/lib/api/findings";
import { listProjectScans } from "@/lib/api/scans";
import { SEVERITY_ORDER } from "@/lib/severity";

function settledValue(result) {
  if (result.status === "fulfilled") {
    return { data: result.value, error: null };
  }
  return {
    data: null,
    error: result.reason?.message || "Unable to load security data.",
  };
}

function scanItems(payload) {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.items)) return payload.items;
  return [];
}

function asList(payload) {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.items)) return payload.items;
  return [];
}

export function selectCurrentRiskScan(scans) {
  return [...scans]
    .filter((scan) => scan?.risk_score != null && !Number.isNaN(Number(scan.risk_score)))
    .sort((left, right) => {
      const rightTime = Date.parse(right.created_at || "") || 0;
      const leftTime = Date.parse(left.created_at || "") || 0;
      return rightTime - leftTime;
    })[0] || null;
}

export function countBySeverity(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    const key = String(finding?.severity || "").toLowerCase();
    if (key in counts) {
      counts[key] += 1;
    } else {
      counts.info += 1;
    }
  }

  return counts;
}

export function countByAssetType(assets) {
  const counts = {};
  for (const asset of assets) {
    const key = String(asset?.asset_type || "unknown").toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

export function rankFindings(findings, limit = 8) {
  const rank = Object.fromEntries(SEVERITY_ORDER.map((key, index) => [key, index]));
  return [...findings]
    .sort((left, right) => {
      const severityDelta =
        (rank[String(left.severity || "").toLowerCase()] ?? 99) -
        (rank[String(right.severity || "").toLowerCase()] ?? 99);
      if (severityDelta !== 0) return severityDelta;
      return (Number(right.score) || 0) - (Number(left.score) || 0);
    })
    .slice(0, limit);
}

export async function loadProjectDashboard(projectId) {
  if (!projectId) {
    return {
      securitySummary: { data: null, error: "No project selected.", loaded: false },
      attackPaths: { data: null, error: "No project selected.", loaded: false },
      scans: { items: [], error: "No project selected.", loaded: false },
      findings: { items: [], error: "No project selected.", loaded: false },
      assets: { items: [], error: "No project selected.", loaded: false },
    };
  }

  const [securityResult, attackPathsResult, scansResult, findingsResult, assetsResult] =
    await Promise.allSettled([
      getProjectSecuritySummary(projectId),
      getProjectAttackPaths(projectId, { max_paths: 50, max_depth: 5 }),
      listProjectScans(projectId, { page: 1, page_size: 20 }),
      listProjectFindings(projectId, { page: 1, page_size: 100 }),
      listProjectAssets(projectId, { page: 1, page_size: 500 }),
    ]);

  const securitySummary = settledValue(securityResult);
  const attackPaths = settledValue(attackPathsResult);
  const scans = settledValue(scansResult);
  const findings = settledValue(findingsResult);
  const assets = settledValue(assetsResult);

  return {
    securitySummary: {
      data: securitySummary.data || null,
      error: securitySummary.error,
      loaded: !securitySummary.error && securitySummary.data != null,
    },
    attackPaths: {
      data: attackPaths.data || { paths: [], total: 0, truncated: false },
      error: attackPaths.error,
      loaded: !attackPaths.error && attackPaths.data != null,
    },
    scans: {
      items: scanItems(scans.data),
      raw: scans.data,
      error: scans.error,
      loaded: !scans.error,
    },
    findings: {
      items: asList(findings.data),
      raw: findings.data,
      error: findings.error,
      loaded: !findings.error,
    },
    assets: {
      items: asList(assets.data),
      raw: assets.data,
      error: assets.error,
      loaded: !assets.error,
    },
  };
}

// Backward-compat: old callers used listTargets etc. Keep helpers for fallback
export function legacyCountBySeverity(findings) {
  return countBySeverity(findings);
}
