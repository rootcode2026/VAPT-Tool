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

function SectionLink({ href, children }) {
  return (
    <Link href={href} className="text-xs font-medium text-primary hover:underline">
      {children}
    </Link>
  );
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
        <ErrorState
          title="Unable to load security data."
          message={projectError}
          onRetry={refreshProjects}
        />
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

  const findings = snapshot?.findings.items || [];
  const scans = snapshot?.scans.items || [];
  const assets = snapshot?.assets.items || [];
  const severityCounts = snapshot?.findings.loaded ? countBySeverity(findings) : null;
  const assetCounts = snapshot?.assets.loaded ? countByAssetType(assets) : null;
  const riskScan = snapshot?.scans.loaded ? selectCurrentRiskScan(scans) : null;
  const latestScan = scans[0] || null;
  const topFindings = snapshot?.findings.loaded ? rankFindings(findings) : [];

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

      {loadError ? (
        <ErrorState
          title="Unable to load security data."
          message={loadError}
          onRetry={refresh}
        />
      ) : null}

      {loading && !snapshot ? (
        <SkeletonCards count={4} />
      ) : (
        <>
          <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <RiskScoreCard
              label="Risk score"
              score={snapshot?.scans.loaded ? riskScan?.risk_score : null}
              grade={snapshot?.scans.loaded ? riskScan?.risk_grade : null}
              description={
                !snapshot?.scans.loaded
                  ? "Data unavailable."
                  : formatLevel(riskScan?.risk_level) ||
                    (scans.length === 0
                      ? "No scans yet."
                      : riskScan
                        ? "From the latest scan with a backend risk score."
                        : "Not available")
              }
            />
            <StatCard
              label="Critical findings"
              unavailable={!snapshot?.findings.loaded}
              value={
                snapshot?.findings.loaded
                  ? severityCounts.critical
                  : "Not available"
              }
            />
            <StatCard
              label="High findings"
              unavailable={!snapshot?.findings.loaded}
              value={
                snapshot?.findings.loaded ? severityCounts.high : "Not available"
              }
            />
            <StatCard
              label="Total findings"
              unavailable={!snapshot?.findings.loaded}
              value={
                snapshot?.findings.loaded ? findings.length : "Not available"
              }
            />
            <StatCard
              label="Assets"
              unavailable={!snapshot?.assets.loaded}
              value={snapshot?.assets.loaded ? assets.length : "Not available"}
            />
            <StatCard
              label="Recent scans"
              unavailable={!snapshot?.scans.loaded}
              value={snapshot?.scans.loaded ? scans.length : "Not available"}
              hint={selectedProject?.name}
            />
          </section>

          <div className="grid gap-4 xl:grid-cols-3">
            <DashboardSection title="Security posture">
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <dt className="text-muted">Risk grade</dt>
                  <dd className="mt-1 font-medium">
                    {snapshot?.scans.loaded
                      ? riskScan?.risk_grade || "Not available"
                      : "Data unavailable."}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">Risk score</dt>
                  <dd className="mt-1 font-medium tabular-nums">
                    {snapshot?.scans.loaded
                      ? riskScan?.risk_score ?? "Not available"
                      : "Data unavailable."}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">Critical findings</dt>
                  <dd className="mt-1 font-medium tabular-nums">
                    {snapshot?.findings.loaded
                      ? severityCounts.critical
                      : "Data unavailable."}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">High findings</dt>
                  <dd className="mt-1 font-medium tabular-nums">
                    {snapshot?.findings.loaded
                      ? severityCounts.high
                      : "Data unavailable."}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">Assets</dt>
                  <dd className="mt-1 font-medium tabular-nums">
                    {snapshot?.assets.loaded ? assets.length : "Data unavailable."}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">Last scan</dt>
                  <dd className="mt-1 font-medium">
                    {snapshot?.scans.loaded
                      ? latestScan
                        ? formatWhen(latestScan.created_at)
                        : "No scans yet."
                      : "Data unavailable."}
                  </dd>
                </div>
              </dl>
            </DashboardSection>

            <DashboardSection
              title="Severity overview"
              action={<SectionLink href="/findings">View findings</SectionLink>}
            >
              {!snapshot?.findings.loaded ? (
                <ErrorState
                  title="Unable to load security data."
                  message={snapshot?.findings.error}
                  onRetry={refresh}
                />
              ) : findings.length === 0 ? (
                <EmptyState
                  title="No vulnerabilities detected."
                  description="The findings API returned no results for this project."
                />
              ) : (
                <SeverityDistribution counts={severityCounts} />
              )}
            </DashboardSection>

            <DashboardSection
              title="Asset overview"
              action={
                <div className="flex gap-3">
                  <SectionLink href="/assets">View assets</SectionLink>
                  <SectionLink href="/attack-surface">View attack surface</SectionLink>
                </div>
              }
            >
              {!snapshot?.assets.loaded ? (
                <ErrorState
                  title="Unable to load security data."
                  message={snapshot?.assets.error}
                  onRetry={refresh}
                />
              ) : assets.length === 0 ? (
                <EmptyState
                  title="No security data available yet."
                  description="No assets have been discovered for this project."
                />
              ) : (
                <AssetTypeSummary counts={assetCounts} />
              )}
            </DashboardSection>
          </div>

          <DashboardSection
            title="Top findings"
            action={<SectionLink href="/findings">View all findings</SectionLink>}
          >
            {loading && !snapshot?.findings.loaded ? (
              <SkeletonTable rows={4} />
            ) : !snapshot?.findings.loaded ? (
              <ErrorState
                title="Unable to load security data."
                message={snapshot?.findings.error}
                onRetry={refresh}
              />
            ) : topFindings.length === 0 ? (
              <EmptyState title="No vulnerabilities detected." />
            ) : (
              <DataTable
                rowKey={(row) => row.id}
                columns={[
                  {
                    key: "severity",
                    header: "Severity",
                    render: (row) => <SeverityBadge severity={row.severity} />,
                  },
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
                  {
                    key: "status",
                    header: "Status",
                    render: (row) => <StatusBadge status={row.status} />,
                  },
                  {
                    key: "score",
                    header: "Score",
                    render: (row) =>
                      row.score == null ? "—" : row.score,
                  },
                  {
                    key: "created_at",
                    header: "Created",
                    render: (row) =>
                      row.created_at ? formatWhen(row.created_at) : "—",
                  },
                ]}
                rows={topFindings}
              />
            )}
          </DashboardSection>

          <DashboardSection
            title="Recent scans"
            action={<SectionLink href="/scans">View scans</SectionLink>}
          >
            {!snapshot?.scans.loaded ? (
              <ErrorState
                title="Unable to load security data."
                message={snapshot?.scans.error}
                onRetry={refresh}
              />
            ) : scans.length === 0 ? (
              <EmptyState
                title="No scans yet."
                description="Start a scan to generate risk scores and findings for this project."
                action={
                  <Link
                    href="/scans"
                    className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground"
                  >
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
                  {
                    key: "status",
                    header: "Status",
                    render: (row) => <StatusBadge status={row.status} />,
                  },
                  {
                    key: "risk",
                    header: "Risk",
                    render: (row) =>
                      row.risk_score == null
                        ? "Not available"
                        : `${row.risk_score}${row.risk_grade ? ` (${row.risk_grade})` : ""}`,
                  },
                  {
                    key: "created_at",
                    header: "Created",
                    render: (row) => formatWhen(row.created_at),
                  },
                ]}
                rows={scans.slice(0, 8)}
              />
            )}
          </DashboardSection>
        </>
      )}
    </div>
  );
}
