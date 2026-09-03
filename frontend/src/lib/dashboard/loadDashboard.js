import { listAssets } from "@/lib/api/assets";
import { listFindings } from "@/lib/api/findings";
import { listScans } from "@/lib/api/scans";
import { listTargets } from "@/lib/api/targets";
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
  return Array.isArray(payload) ? payload : [];
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
  const [targetsResult, scansResult, findingsResult, assetsResult] =
    await Promise.allSettled([
      listTargets(),
      listScans({ page: 1, page_size: 100 }),
      listFindings(),
      listAssets({ project_id: projectId, limit: 500 }),
    ]);

  const targets = settledValue(targetsResult);
  const scans = settledValue(scansResult);
  const findings = settledValue(findingsResult);
  const assets = settledValue(assetsResult);

  const projectTargets = asList(targets.data).filter(
    (target) => target.project_id === projectId
  );
  const targetIds = new Set(projectTargets.map((target) => target.id));

  const projectScans = scanItems(scans.data).filter((scan) =>
    targetIds.has(scan.target_id)
  );
  const projectFindings = asList(findings.data).filter((finding) =>
    targetIds.has(finding.target_id)
  );
  const projectAssets = asList(assets.data);

  return {
    targets: {
      items: projectTargets,
      error: targets.error,
      loaded: !targets.error,
    },
    scans: {
      items: projectScans,
      error: scans.error,
      loaded: !scans.error,
    },
    findings: {
      items: projectFindings,
      error: findings.error,
      loaded: !findings.error,
    },
    assets: {
      items: projectAssets,
      error: assets.error,
      loaded: !assets.error,
    },
  };
}
