"use client";

/* eslint-disable react-hooks/set-state-in-effect -- intentional project-scoped state reset with request cancellation */
import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import DashboardSection from "@/components/dashboard/DashboardSection";
import ProjectSelect from "@/components/layout/ProjectSelect";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import FilterBar from "@/components/ui/FilterBar";
import PageHeader from "@/components/ui/PageHeader";
import SearchInput from "@/components/ui/SearchInput";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { SkeletonCards, SkeletonTable } from "@/components/ui/Skeleton";
import StatCard from "@/components/ui/StatCard";
import StatusBadge from "@/components/ui/StatusBadge";
import { getAsset, listProjectAssets, getProjectSecuritySummary } from "@/lib/api/assets";
import { useProjectContext } from "@/lib/project-context";

const ASSET_TYPES = [
  "",
  "domain",
  "subdomain",
  "ip",
  "ipv6",
  "url",
  "port",
  "service",
  "technology",
  "hostname",
  "dns_cname",
  "dns_mx",
  "dns_ns",
];

const STATUS_OPTIONS = ["", "active", "stale", "inactive"];

function formatWhen(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function formatAssetType(value) {
  if (!value) return "—";
  return String(value).replaceAll("_", " ");
}

export default function AssetsPage() {
  const { selectedProjectId, selectedProject, status: projectStatus, error: projectError } = useProjectContext();

  const [summary, setSummary] = useState(null);
  const [summaryError, setSummaryError] = useState("");
  const [summaryLoaded, setSummaryLoaded] = useState(false);

  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [assetType, setAssetType] = useState("");
  const [status, setStatus] = useState("");

  const [selectedAssetId, setSelectedAssetId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");

  const requestRef = useRef(0);
  const detailRef = useRef(0);

  // Debounce search
  useEffect(() => {
    const id = window.setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => window.clearTimeout(id);
  }, [search]);

  // Reset pagination and selection when project or filters change
  useEffect(() => {
    setPage(1);
    setSelectedAssetId(null);
    setDetail(null);
    setDetailError("");
  }, [selectedProjectId, debouncedSearch, assetType, status]);

  const loadSummary = useCallback(async (projectId) => {
    if (!projectId) {
      setSummary(null);
      setSummaryLoaded(false);
      return;
    }
    try {
      const data = await getProjectSecuritySummary(projectId);
      setSummary(data);
      setSummaryLoaded(true);
      setSummaryError("");
    } catch (err) {
      setSummary(null);
      setSummaryLoaded(false);
      setSummaryError(err.message || "Unable to load security data.");
    }
  }, []);

  const loadAssets = useCallback(
    async (projectId, p, searchVal, typeVal, statusVal) => {
      if (!projectId) {
        setAssets([]);
        setTotal(0);
        setTotalPages(0);
        return;
      }
      const reqId = requestRef.current + 1;
      requestRef.current = reqId;
      setLoading(true);
      setError("");
      try {
        const query = {
          page: p,
          page_size: pageSize,
        };
        if (searchVal) query.search = searchVal;
        if (typeVal) query.asset_type = typeVal;
        if (statusVal) query.status = statusVal;
        const data = await listProjectAssets(projectId, query);
        if (requestRef.current !== reqId) return;
        // listProjectAssets returns paginated dict {items, total, ...} or list
        const items = Array.isArray(data) ? data : data.items || [];
        const t = Array.isArray(data) ? items.length : data.total ?? items.length;
        const tp = Array.isArray(data) ? 1 : data.total_pages ?? Math.ceil(t / pageSize);
        setAssets(items);
        setTotal(t);
        setTotalPages(tp);
      } catch (err) {
        if (requestRef.current !== reqId) return;
        setAssets([]);
        setError(err.message || "Unable to load security data.");
      } finally {
        if (requestRef.current === reqId) setLoading(false);
      }
    },
    [pageSize]
  );

  // Load summary on project change
  useEffect(() => {
    if (projectStatus !== "ready") return undefined;
    loadSummary(selectedProjectId);
    return undefined;
  }, [projectStatus, selectedProjectId, loadSummary]);

  // Load assets when dependencies change
  useEffect(() => {
    if (projectStatus !== "ready") return undefined;
    const id = window.setTimeout(() => {
      loadAssets(selectedProjectId, page, debouncedSearch, assetType, status);
    }, 0);
    return () => window.clearTimeout(id);
  }, [projectStatus, selectedProjectId, page, debouncedSearch, assetType, status, loadAssets]);

  // Load asset detail when selected
  const loadDetail = useCallback(async (assetId) => {
    if (!assetId) {
      setDetail(null);
      return;
    }
    const reqId = detailRef.current + 1;
    detailRef.current = reqId;
    setDetailLoading(true);
    setDetailError("");
    try {
      const data = await getAsset(assetId);
      if (detailRef.current !== reqId) return;
      setDetail(data);
    } catch (err) {
      if (detailRef.current !== reqId) return;
      setDetail(null);
      setDetailError(err.message || "Unable to load security data.");
    } finally {
      if (detailRef.current === reqId) setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedAssetId) loadDetail(selectedAssetId);
    else {
      setDetail(null);
      setDetailError("");
    }
  }, [selectedAssetId, loadDetail]);

  // Clear stale detail when project switches
  useEffect(() => {
    setSelectedAssetId(null);
    setDetail(null);
    setDetailError("");
  }, [selectedProjectId]);

  if (projectStatus === "loading") {
    return (
      <div>
        <PageHeader title="Asset Intelligence" description="Investigate discovered assets, their security context, and relationships." />
        <SkeletonCards count={4} />
      </div>
    );
  }

  if (projectStatus === "error") {
    return (
      <div>
        <PageHeader title="Asset Intelligence" description="Investigate discovered assets, their security context, and relationships." />
        <ErrorState title="Unable to load security data." message={projectError} />
      </div>
    );
  }

  if (!selectedProjectId) {
    return (
      <div>
        <PageHeader title="Asset Intelligence" description="Investigate discovered assets, their security context, and relationships." />
        <EmptyState
          title="No projects yet."
          description="Create a project to start monitoring assets."
          action={
            <Link href="/projects" className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">
              Create Project
            </Link>
          }
        />
      </div>
    );
  }

  const assetTypeLabel = (v) => (v ? formatAssetType(v) : "All types");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Asset Intelligence"
        description="Investigate the project's discovered assets and their security context."
        actions={
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Project</span>
            <ProjectSelect id="assets-project-context" />
          </label>
        }
      />

      {/* Summary */}
      {summaryLoaded ? (
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5" aria-label="Asset summary">
          <StatCard label="Total assets" value={summary?.total_assets ?? 0} />
          <StatCard label="Internet-facing" value={summary?.internet_facing_assets ?? 0} />
          <StatCard label="Vulnerable" value={summary?.vulnerable_assets ?? 0} />
          <StatCard label="Critical" value={summary?.critical_assets ?? 0} />
          <StatCard label="Exposed services" value={summary?.exposed_service_assets ?? 0} />
        </section>
      ) : summaryError ? (
        <ErrorState title="Unable to load security data." message={summaryError} onRetry={() => loadSummary(selectedProjectId)} />
      ) : (
        <SkeletonCards count={5} />
      )}

      {/* Filters */}
      <FilterBar>
        <SearchInput value={search} onChange={setSearch} placeholder="Search by value" id="assets-search" label="Search assets" />
        <select
          value={assetType}
          onChange={(e) => setAssetType(e.target.value)}
          className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text"
          aria-label="Filter by asset type"
        >
          {ASSET_TYPES.map((t) => (
            <option key={t || "all"} value={t}>
              {t ? formatAssetType(t) : "All types"}
            </option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text"
          aria-label="Filter by status"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s || "all"} value={s}>
              {s || "All statuses"}
            </option>
          ))}
        </select>
        {(assetType || status || debouncedSearch) && (
          <button
            type="button"
            onClick={() => {
              setSearch("");
              setAssetType("");
              setStatus("");
            }}
            className="rounded-sm border border-border px-3 py-1.5 text-sm text-text hover:bg-surface-hover"
          >
            Clear filters
          </button>
        )}
        <span className="text-xs text-muted">
          {total} assets {selectedProject?.name ? `in ${selectedProject.name}` : ""}
        </span>
      </FilterBar>

      {/* Inventory + Detail */}
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          {loading ? (
            <SkeletonTable rows={6} />
          ) : error ? (
            <ErrorState title="Unable to load security data." message={error} onRetry={() => loadAssets(selectedProjectId, page, debouncedSearch, assetType, status)} />
          ) : assets.length === 0 ? (
            <EmptyState title="No assets" description="No assets match the current filters for this project. Try adjusting search or filters." />
          ) : (
            <>
              <DataTable
                rowKey={(row) => row.id}
                columns={[
                  { key: "asset_type", header: "Type", render: (row) => <span className="font-medium">{formatAssetType(row.asset_type)}</span> },
                  {
                    key: "value",
                    header: "Value",
                    render: (row) => (
                      <button
                        type="button"
                        onClick={() => setSelectedAssetId(row.id)}
                        className={`text-left hover:underline ${selectedAssetId === row.id ? "font-semibold text-primary" : ""}`}
                      >
                        {row.value}
                      </button>
                    ),
                  },
                  { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
                  {
                    key: "exposure",
                    header: "Exposure",
                    render: (row) => {
                      // Use classifications if available in list? List does not include, so show status-based fallback
                      // Detail will show precise exposure
                      return <span className="text-xs text-muted">View detail</span>;
                    },
                  },
                  { key: "last_seen_at", header: "Last seen", render: (row) => formatWhen(row.last_seen_at) },
                  { key: "first_seen_at", header: "First seen", render: (row) => formatWhen(row.first_seen_at) },
                ]}
                rows={assets}
                empty={<EmptyState title="No assets" />}
              />
              {/* Pagination */}
              <div className="mt-4 flex items-center justify-between gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="rounded-sm border border-border px-3 py-1.5 text-sm disabled:opacity-50"
                >
                  Previous
                </button>
                <span className="text-xs text-muted">
                  Page {page} of {totalPages || 1} — {total} total
                </span>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="rounded-sm border border-border px-3 py-1.5 text-sm disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </>
          )}
        </div>

        {/* Detail panel */}
        <div className="xl:col-span-1">
          {!selectedAssetId ? (
            <div className="rounded-md border border-dashed border-border bg-surface p-6 text-center">
              <p className="text-sm font-medium text-text">Select an asset</p>
              <p className="mt-1 text-xs text-muted">Choose an asset from the inventory to inspect its security context, relationships, and findings.</p>
            </div>
          ) : detailLoading ? (
            <div className="space-y-3">
              <div className="h-6 w-32 animate-pulse rounded bg-surface-hover" />
              <div className="h-24 w-full animate-pulse rounded bg-surface-hover" />
              <SkeletonTable rows={3} />
            </div>
          ) : detailError ? (
            <ErrorState title="Unable to load security data." message={detailError} onRetry={() => loadDetail(selectedAssetId)} />
          ) : detail ? (
            <div className="space-y-4">
              <div className="rounded-md border border-border bg-surface p-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted">{formatAssetType(detail.asset_type)}</p>
                    <h3 className="mt-1 break-all text-sm font-semibold text-text">{detail.value}</h3>
                    <p className="mt-1 text-xs text-muted">ID: {detail.id}</p>
                  </div>
                  <button type="button" onClick={() => setSelectedAssetId(null)} className="text-xs text-muted hover:text-text">
                    Close
                  </button>
                </div>
                <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <dt className="text-muted">Status</dt>
                    <dd className="mt-1"><StatusBadge status={detail.status} /></dd>
                  </div>
                  <div>
                    <dt className="text-muted">First seen</dt>
                    <dd className="mt-1 font-medium">{formatWhen(detail.first_seen_at)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Last seen</dt>
                    <dd className="mt-1 font-medium">{formatWhen(detail.last_seen_at)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Project</dt>
                    <dd className="mt-1 font-medium">{selectedProject?.name || detail.project_id}</dd>
                  </div>
                </dl>
                {detail.metadata && Object.keys(detail.metadata).length > 0 && (
                  <div className="mt-4 rounded-sm bg-canvas p-3">
                    <p className="text-xs font-medium text-muted">Metadata</p>
                    <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-words text-xs text-text">{JSON.stringify(detail.metadata, null, 2)}</pre>
                  </div>
                )}
              </div>

              {/* Classifications */}
              <div className="rounded-md border border-border bg-surface p-4">
                <h4 className="text-sm font-semibold text-text">Exposure & Classifications</h4>
                {detail.classifications ? (
                  <ul className="mt-3 grid grid-cols-2 gap-2 text-xs">
                    {Object.entries(detail.classifications).map(([k, v]) => (
                      <li key={k} className={`rounded-sm border px-2 py-1.5 ${v ? "border-success/30 bg-success/10" : "border-border bg-canvas"}`}>
                        <span className="text-muted">{k.replaceAll("_", " ")}:</span> <span className="font-medium">{v ? "Yes" : "No"}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-2 text-xs text-muted">Not available</p>
                )}
                {detail.security_signals?.exposure_signal ? (
                  <div className="mt-3 text-xs">
                    <p className="font-medium">Exposure signals</p>
                    <ul className="mt-1 list-disc pl-4 text-muted">
                      <li>Internet-facing: {detail.security_signals.exposure_signal.internet_facing ? "Yes" : "No"}</li>
                      <li>Web application: {detail.security_signals.exposure_signal.web_application ? "Yes" : "No"}</li>
                      <li>Exposed service: {detail.security_signals.exposure_signal.exposed_service ? "Yes" : "No"}</li>
                    </ul>
                  </div>
                ) : null}
              </div>

              {/* Contextual risk */}
              <div className="rounded-md border border-border bg-surface p-4">
                <h4 className="text-sm font-semibold text-text">Contextual risk</h4>
                {detail.contextual_risk ? (
                  <>
                    <p className="mt-2 text-xs">
                      <span className="text-muted">Priority:</span> <span className="font-semibold">{detail.contextual_risk.priority || "informational"}</span>
                    </p>
                    <p className="mt-1 text-xs text-muted">{detail.contextual_risk.explanation}</p>
                    {detail.contextual_risk.risk_factors?.length ? (
                      <ul className="mt-2 space-y-1">
                        {detail.contextual_risk.risk_factors.map((f) => (
                          <li key={f.code} className="text-xs">
                            <span className="font-medium">{f.code}</span> — {f.description}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </>
                ) : (
                  <p className="mt-2 text-xs text-muted">Not available</p>
                )}
                {detail.security_summary && (
                  <dl className="mt-3 grid grid-cols-3 gap-2 text-xs">
                    <div><dt className="text-muted">Findings</dt><dd className="font-medium">{detail.security_summary.total_findings ?? 0}</dd></div>
                    <div><dt className="text-muted">Critical</dt><dd className="font-medium text-critical">{detail.security_summary.critical ?? 0}</dd></div>
                    <div><dt className="text-muted">High</dt><dd className="font-medium text-high">{detail.security_summary.high ?? 0}</dd></div>
                  </dl>
                )}
              </div>

              {/* Relationships */}
              <div className="rounded-md border border-border bg-surface p-4">
                <h4 className="text-sm font-semibold text-text">Relationships</h4>
                {!detail.relationships || detail.relationships.length === 0 ? (
                  <p className="mt-2 text-xs text-muted">No relationships for this asset.</p>
                ) : (
                  <ul className="mt-3 space-y-2">
                    {detail.relationships.map((rel) => {
                      const isOutgoing = rel.direction === "outgoing";
                      const related = rel.asset || (isOutgoing ? rel.target_asset : rel.source_asset);
                      const arrow = "↓";
                      return (
                        <li key={rel.relationship_id} className="rounded-sm border border-border bg-canvas px-3 py-2">
                          <p className="text-xs font-medium text-text">
                            {isOutgoing ? detail.value : related?.value} <span className="mx-2 text-muted">{arrow} {rel.relationship_type} {arrow}</span> {isOutgoing ? related?.value : detail.value}
                          </p>
                          <p className="mt-1 text-xs text-muted">
                            {isOutgoing ? `${detail.asset_type} → ${related?.asset_type}` : `${related?.asset_type} → ${detail.asset_type}`} • {rel.direction}
                          </p>
                          {related && (
                            <p className="text-xs text-muted">{related.asset_type}: {related.value}</p>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>

              {/* Findings */}
              <div className="rounded-md border border-border bg-surface p-4">
                <h4 className="text-sm font-semibold text-text">Findings</h4>
                {!detail.findings || detail.findings.length === 0 ? (
                  <p className="mt-2 text-xs text-muted">No findings associated with this asset.</p>
                ) : (
                  <ul className="mt-3 space-y-2">
                    {detail.findings.map((f) => (
                      <li key={f.id} className="rounded-sm border border-border bg-canvas px-3 py-2">
                        <div className="flex items-start justify-between gap-2">
                          <Link href={`/findings/${f.id}`} className="text-xs font-medium hover:underline">
                            {f.title}
                          </Link>
                          <SeverityBadge severity={f.severity} />
                        </div>
                        <p className="mt-1 flex flex-wrap gap-2 text-xs">
                          <span className="rounded-sm border px-1.5 py-0.5">Status: {f.status}</span>
                          <span className="rounded-sm border px-1.5 py-0.5">Scanner: {f.scanner}</span>
                          {f.score != null && <span className="rounded-sm border px-1.5 py-0.5">Risk: {f.score}</span>}
                        </p>
                        {f.evidence && <p className="mt-1 text-xs text-muted line-clamp-2">Evidence: {f.evidence}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
