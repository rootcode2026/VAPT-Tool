"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import AssetTypeSummary from "@/components/dashboard/AssetTypeSummary";
import DashboardSection from "@/components/dashboard/DashboardSection";
import SeverityDistribution from "@/components/dashboard/SeverityDistribution";
import ProjectSelect from "@/components/layout/ProjectSelect";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import PageHeader from "@/components/ui/PageHeader";
import RiskScoreCard from "@/components/ui/RiskScoreCard";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { SkeletonCards, SkeletonTable } from "@/components/ui/Skeleton";
import StatCard from "@/components/ui/StatCard";
import StatusBadge from "@/components/ui/StatusBadge";
import {
  countByAssetType,
  countBySeverity,
  loadProjectDashboard,
  rankFindings,
  selectCurrentRiskScan,
} from "@/lib/dashboard/loadDashboard";
import { useProjectContext } from "@/lib/project-context";

function formatWhen(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

function formatLevel(value) {
  if (!value) return null;
  return String(value).replaceAll("_", " ");
}

function formatPriority(value) {
  if (!value) return "Not available";
  return String(value).charAt(0).toUpperCase() + String(value).slice(1);
}

function SectionLink({ href, children }) {
  return (
    <Link href={href} className="text-xs font-medium text-primary hover:underline">
      {children}
    </Link>
  );
}

function Unavailable({ label = "Not available" }) {
  return <span className="text-muted">{label}</span>;
}

export default function DashboardPage() {
  const {
    selectedProjectId,
    selectedProject,
    status: projectStatus,
    error: projectError,
    refreshProjects,
  } = useProjectContext();

  const [snapshot, setSnapshot] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const requestRef = useRef(0);

  const loadData = useCallback(async (projectId) => {
    if (!projectId) {
      setSnapshot(null);
      setLoadError("");
      setLoading(false);
      return;
    }

    const requestId = requestRef.current + 1;
    requestRef.current = requestId;
    setLoading(true);
    setLoadError("");

    try {
      const data = await loadProjectDashboard(projectId);
      if (requestRef.current !== requestId) return;
      setSnapshot(data);
    } catch (err) {
      if (requestRef.current !== requestId) return;
      setSnapshot(null);
      setLoadError(err.message || "Unable to load security data.");
    } finally {
      if (requestRef.current === requestId) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    if (projectStatus !== "ready") return undefined;
    const id = window.setTimeout(() => {
      loadData(selectedProjectId);
    }, 0);
    return () => window.clearTimeout(id);
  }, [projectStatus, selectedProjectId, loadData]);

  async function refresh() {
    if (loading) return;
    await refreshProjects({ silent: true });
    await loadData(selectedProjectId);
  }

  if (projectStatus === "loading") {
    return (
      <div>
        <PageHeader
          title="Security Overview"
          description="Monitor your security posture, vulnerabilities, and attack surface."
        />
        <SkeletonCards count={4} />
      </div>
    );
  }

  if (projectStatus === "error") {
    return (
      <div>
        <PageHeader
          title="Security Overview"
          description="Monitor your security posture, vulnerabilities, and attack surface."
        />
        <ErrorState title="Unable to load security data." message={projectError} onRetry={refreshProjects} />
      </div>
    );
  }

  if (!selectedProjectId) {
    return (
      <div>
        <PageHeader
          title="Security Overview"
          description="Monitor your security posture, vulnerabilities, and attack surface."
        />
        <EmptyState
          title="No projects yet."
          description="Create a project to start monitoring security posture, findings, and assets."
          action={
            <Link
              href="/projects"
              className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground"
            >
              Create Project
            </Link>
          }
        />
      </div>
    );
  }

  const security = snapshot?.securitySummary?.data || null;
  const securityLoaded = Boolean(snapshot?.securitySummary?.loaded);
  const securityError = snapshot?.securitySummary?.error || null;

  const attackPaths = snapshot?.attackPaths?.data || { paths: [], total: 0, truncated: false };
  const attackLoaded = Boolean(snapshot?.attackPaths?.loaded);
  const attackError = snapshot?.attackPaths?.error || null;

  const scans = snapshot?.scans?.items || [];
  const scansLoaded = Boolean(snapshot?.scans?.loaded);
  const scansError = snapshot?.scans?.error || null;

  const findings = snapshot?.findings?.items || [];
  const findingsLoaded = Boolean(snapshot?.findings?.loaded);
  const findingsError = snapshot?.findings?.error || null;

  const assets = snapshot?.assets?.items || [];
  const assetsLoaded = Boolean(snapshot?.assets?.loaded);
  const assetsError = snapshot?.assets?.error || null;

  const severityCounts = findingsLoaded ? countBySeverity(findings) : null;
  const assetCounts = assetsLoaded ? countByAssetType(assets) : null;
  const riskScan = scansLoaded ? selectCurrentRiskScan(scans) : null;
  const latestScan = scans[0] || null;
  const topFindings = findingsLoaded ? rankFindings(findings, 6) : [];
  const topPaths = attackLoaded ? (attackPaths.paths || []).slice(0, 5) : [];

  const isInitialLoading = loading && !snapshot;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Overview"
        description="Monitor your security posture, vulnerabilities, and attack surface."
        actions={
          <>
            <label className="flex items-center gap-2 text-sm">
              <span className="text-muted">Project</span>
              <ProjectSelect id="dashboard-project-context" />
            </label>
            <button
              type="button"
              onClick={refresh}
              disabled={loading}
              className="rounded-sm border border-border px-3 py-1.5 text-sm text-text hover:bg-surface-hover disabled:opacity-60"
            >
              {loading ? "Refreshing..." : "Refresh"}
            </button>
            <Link
              href="/scans"
              className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground"
            >
              New Scan
            </Link>
          </>
        }
      />

      {loadError ? <ErrorState title="Unable to load security data." message={loadError} onRetry={refresh} /> : null}

      {/* 1 — Security overview cards (5) */}
      {isInitialLoading ? (
        <SkeletonCards count={5} />
      ) : (
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5" aria-label="Security overview">
          <StatCard
            label="Total assets"
            unavailable={!securityLoaded}
            value={securityLoaded ? security?.total_assets ?? 0 : "Not available"}
            hint={selectedProject?.name}
          />
          <StatCard
            label="Internet-facing"
            unavailable={!securityLoaded}
            value={securityLoaded ? security?.internet_facing_assets ?? 0 : "Not available"}
          />
          <StatCard
            label="Vulnerable assets"
            unavailable={!securityLoaded}
            value={securityLoaded ? security?.vulnerable_assets ?? 0 : "Not available"}
          />
          <StatCard
            label="Critical assets"
            unavailable={!securityLoaded}
            value={securityLoaded ? security?.critical_assets ?? 0 : "Not available"}
          />
          <StatCard
            label="Attack paths"
            unavailable={!attackLoaded}
            value={attackLoaded ? attackPaths.total ?? 0 : "Not available"}
            hint={attackLoaded && attackPaths.truncated ? "Truncated" : undefined}
          />
        </section>
      )}

      {/* 2 + 3 + 4 — Risk, Asset, Attack-path overviews */}
      {isInitialLoading ? (
        <SkeletonCards count={3} />
      ) : (
        <div className="grid gap-4 xl:grid-cols-3">
          {/* Risk overview */}
          <DashboardSection title="Risk overview" action={<SectionLink href="/findings">View findings</SectionLink>}>
            {!findingsLoaded ? (
              <ErrorState title="Unable to load security data." message={findingsError} onRetry={refresh} />
            ) : !securityLoaded ? (
              <ErrorState title="Unable to load security data." message={securityError} onRetry={refresh} />
            ) : (
              <div className="space-y-4">
                <dl className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <dt className="text-muted">Critical</dt>
                    <dd className="mt-1 font-semibold tabular-nums text-critical">{security?.critical_assets ?? severityCounts?.critical ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">High</dt>
                    <dd className="mt-1 font-semibold tabular-nums text-high">{security?.high_assets ?? severityCounts?.high ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Medium</dt>
                    <dd className="mt-1 font-semibold tabular-nums text-medium">{security?.medium_assets ?? severityCounts?.medium ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Low</dt>
                    <dd className="mt-1 font-semibold tabular-nums text-low">{security?.low_assets ?? 0}</dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="text-muted">Highest priority</dt>
                    <dd className="mt-1 font-medium">{formatPriority(security?.highest_contextual_priority)}</dd>
                  </div>
                </dl>
                {findingsLoaded && findings.length > 0 ? (
                  <SeverityDistribution counts={severityCounts} />
                ) : findingsLoaded ? (
                  <EmptyState title="No findings" description="No vulnerabilities for this project." />
                ) : null}
                {riskScan ? (
                  <div className="rounded-sm border border-border bg-canvas p-3">
                    <p className="text-xs text-muted">Current risk (latest scan)</p>
                    <p className="mt-1 text-sm font-medium">
                      {riskScan.risk_score != null ? `${riskScan.risk_score} (${riskScan.risk_grade || "—"})` : "Not available"} — {formatLevel(riskScan.risk_level) || "Not available"}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-muted">Risk score not available — run a scan to generate a backend risk score.</p>
                )}
              </div>
            )}
          </DashboardSection>

          {/* Asset overview */}
          <DashboardSection
            title="Asset overview"
            action={
              <div className="flex gap-3">
                <SectionLink href="/assets">View assets</SectionLink>
                <SectionLink href="/attack-surface">View attack surface</SectionLink>
              </div>
            }
          >
            {!assetsLoaded ? (
              <ErrorState title="Unable to load security data." message={assetsError} onRetry={refresh} />
            ) : !securityLoaded ? (
              <ErrorState title="Unable to load security data." message={securityError} onRetry={refresh} />
            ) : assets.length === 0 ? (
              <EmptyState title="No assets" description="No assets have been discovered for this project." />
            ) : (
              <div className="space-y-4">
                <dl className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <dt className="text-muted">Total assets</dt>
                    <dd className="mt-1 font-semibold tabular-nums">{security?.total_assets ?? assets.length}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Exposed</dt>
                    <dd className="mt-1 font-semibold tabular-nums">{security?.exposed_service_assets ?? security?.internet_facing_assets ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Vulnerable</dt>
                    <dd className="mt-1 font-semibold tabular-nums">{security?.vulnerable_assets ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Web apps</dt>
                    <dd className="mt-1 font-semibold tabular-nums">{security?.web_application_assets ?? 0}</dd>
                  </div>
                </dl>
                <AssetTypeSummary counts={assetCounts} />
              </div>
            )}
          </DashboardSection>

          {/* Attack-path overview */}
          <DashboardSection title="Attack-path overview" action={<SectionLink href="/attack-surface">View paths</SectionLink>}>
            {!attackLoaded ? (
              <ErrorState title="Unable to load security data." message={attackError} onRetry={refresh} />
            ) : attackPaths.total === 0 ? (
              <EmptyState title="No attack paths" description="No internet-to-vulnerable paths detected. This may mean no internet-facing assets or no findings — an empty result is expected for isolated projects." />
            ) : (
              <div className="space-y-3">
                <dl className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <dt className="text-muted">Total paths</dt>
                    <dd className="mt-1 font-semibold tabular-nums">{attackPaths.total}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Truncated</dt>
                    <dd className="mt-1 font-medium">{attackPaths.truncated ? "Yes" : "No"}</dd>
                  </div>
                </dl>
                <ul className="space-y-2">
                  {topPaths.map((p) => (
                    <li key={p.path_id} className="rounded-sm border border-border bg-canvas px-3 py-2">
                      <p className="text-xs font-medium text-text">
                        {p.entry_asset_id} → {p.target_asset_id}
                      </p>
                      <p className="mt-1 flex flex-wrap gap-2 text-xs">
                        <span className="rounded-sm border border-border px-1.5 py-0.5">Priority: {p.priority}</span>
                        <span className="rounded-sm border border-border px-1.5 py-0.5">Confidence: {p.confidence}</span>
                        <span className="rounded-sm border border-border px-1.5 py-0.5">Length: {p.length}</span>
                      </p>
                      <p className="mt-1 line-clamp-2 text-xs text-muted">{p.explanation}</p>
                    </li>
                  ))}
                </ul>
                {attackPaths.total > topPaths.length ? (
                  <p className="text-xs text-muted">Showing {topPaths.length} of {attackPaths.total} paths.</p>
                ) : null}
              </div>
            )}
          </DashboardSection>
        </div>
      )}

      {/* Risk score row (kept for backward compat) */}
      {isInitialLoading ? (
        <SkeletonCards count={4} />
      ) : (
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <RiskScoreCard
            label="Risk score"
            score={scansLoaded ? riskScan?.risk_score : null}
            grade={scansLoaded ? riskScan?.risk_grade : null}
            description={
              !scansLoaded
                ? "Data unavailable."
                : formatLevel(riskScan?.risk_level) ||
                  (scans.length === 0 ? "No scans yet." : riskScan ? "From the latest scan with a backend risk score." : "Not available")
            }
          />
          <StatCard label="Critical findings" unavailable={!findingsLoaded} value={findingsLoaded ? countBySeverity(findings).critical : "Not available"} />
          <StatCard label="High findings" unavailable={!findingsLoaded} value={findingsLoaded ? countBySeverity(findings).high : "Not available"} />
          <StatCard label="Total findings" unavailable={!findingsLoaded} value={findingsLoaded ? findings.length : "Not available"} />
        </section>
      )}

      {/* Highest-priority findings */}
      <DashboardSection title="Highest-priority findings" action={<SectionLink href="/findings">View all findings</SectionLink>}>
        {loading && !findingsLoaded ? (
          <SkeletonTable rows={4} />
        ) : !findingsLoaded ? (
          <ErrorState title="Unable to load security data." message={findingsError} onRetry={refresh} />
        ) : topFindings.length === 0 ? (
          <EmptyState title="No vulnerabilities detected." description="The findings API returned no results for this project." />
        ) : (
          <DataTable
            rowKey={(row) => row.id}
            columns={[
              { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
              {
                key: "title",
                header: "Title",
                render: (row) => (
                  <Link href={`/findings/${row.id}`} className="hover:underline">
                    {row.title}
                  </Link>
                ),
              },
              { key: "scanner", header: "Scanner" },
              { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
              {
                key: "score",
                header: "Risk",
                render: (row) => (row.score == null ? "—" : row.score),
              },
              {
                key: "asset",
                header: "Asset",
                render: (row) => row.asset_id || "—",
              },
              { key: "created_at", header: "Created", render: (row) => (row.created_at ? formatWhen(row.created_at) : "—") },
            ]}
            rows={topFindings}
          />
        )}
      </DashboardSection>

      {/* Recent scans */}
      <DashboardSection title="Recent scans" action={<SectionLink href="/scans">View scans</SectionLink>}>
        {!scansLoaded ? (
          <ErrorState title="Unable to load security data." message={scansError} onRetry={refresh} />
        ) : scans.length === 0 ? (
          <EmptyState
            title="No scans yet."
            description="Start a scan to generate risk scores and findings for this project."
            action={
              <Link href="/scans" className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">
                Start your first scan
              </Link>
            }
          />
        ) : (
          <DataTable
            rowKey={(row) => row.id}
            columns={[
              {
                key: "target",
                header: "Target",
                render: (row) => (
                  <Link href={`/scans/${row.id}`} className="hover:underline">
                    {row.target || row.target_id}
                  </Link>
                ),
              },
              { key: "profile", header: "Profile" },
              { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
              {
                key: "progress",
                header: "Progress",
                render: (row) => (row.progress != null ? `${row.progress}%` : "—"),
              },
              {
                key: "findings_count",
                header: "Findings",
                render: (row) => (row.findings_count != null ? row.findings_count : "—"),
              },
              {
                key: "risk",
                header: "Risk",
                render: (row) => (row.risk_score == null ? "Not available" : `${row.risk_score}${row.risk_grade ? ` (${row.risk_grade})` : ""}`),
              },
              { key: "risk_level", header: "Level", render: (row) => formatLevel(row.risk_level) || "—" },
              { key: "created_at", header: "Created", render: (row) => formatWhen(row.created_at) },
            ]}
            rows={scans.slice(0, 8)}
          />
        )}
      </DashboardSection>
    </div>
  );
}
