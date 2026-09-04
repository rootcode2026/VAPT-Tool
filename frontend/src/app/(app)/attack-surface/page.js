"use client";

/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload requires synchronous state reset with stale-request guards */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import {
  getProjectAttackPaths,
  getProjectSecuritySummary,
  listProjectAssets,
} from "@/lib/api/assets";
import { listProjectFindings } from "@/lib/api/findings";
import { useProjectContext } from "@/lib/project-context";

const ASSET_TYPE_OPTIONS = ["", "domain", "subdomain", "ip", "ipv6", "url", "port", "service", "technology", "hostname"];
const STATUS_OPTIONS = ["", "active", "stale", "inactive"];
const PRIORITY_OPTIONS = ["", "critical", "high", "medium", "low", "informational"];
const REL_TYPE_OPTIONS = ["", "contains", "resolves_to", "points_to", "exposes", "runs", "serves", "uses", "observed_on"];

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}
function formatAssetType(v) {
  return v ? String(v).replaceAll("_", " ") : "—";
}

export default function AttackSurfacePage() {
  const { selectedProjectId, selectedProject, status: projectStatus, error: projectError } = useProjectContext();

  // Summary
  const [summary, setSummary] = useState(null);
  const [summaryError, setSummaryError] = useState("");
  const [summaryLoaded, setSummaryLoaded] = useState(false);

  // Assets (for internet-facing section)
  const [assets, setAssets] = useState([]);
  const [assetsTotal, setAssetsTotal] = useState(0);
  const [assetsPage, setAssetsPage] = useState(1);
  const [assetsPageSize] = useState(15);
  const [assetsTotalPages, setAssetsTotalPages] = useState(0);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [assetsError, setAssetsError] = useState("");

  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [assetType, setAssetType] = useState("");
  const [assetStatus, setAssetStatus] = useState("");

  // Relationships
  const [relationships, setRelationships] = useState([]);
  const [relTotal, setRelTotal] = useState(0);
  const [relPage, setRelPage] = useState(1);
  const [relPageSize] = useState(20);
  const [relTotalPages, setRelTotalPages] = useState(0);
  const [relLoading, setRelLoading] = useState(false);
  const [relError, setRelError] = useState("");
  const [relTypeFilter, setRelTypeFilter] = useState("");

  // Attack paths
  const [attackData, setAttackData] = useState({ paths: [], total: 0, truncated: false });
  const [attackLoading, setAttackLoading] = useState(false);
  const [attackError, setAttackError] = useState("");
  const [priorityFilter, setPriorityFilter] = useState("");
  const [selectedPathId, setSelectedPathId] = useState(null);

  // Findings
  const [findings, setFindings] = useState([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsError, setFindingsError] = useState("");
  const [findingsLoaded, setFindingsLoaded] = useState(false);

  const requestRef = useRef(0);

  useEffect(() => {
    const id = window.setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => window.clearTimeout(id);
  }, [search]);

  useEffect(() => {
    setAssetsPage(1);
    setRelPage(1);
    setSelectedPathId(null);
  }, [selectedProjectId, debouncedSearch, assetType, assetStatus, relTypeFilter, priorityFilter]);

  const loadSummary = useCallback(async (projectId, reqId) => {
    try {
      const data = await getProjectSecuritySummary(projectId);
      if (requestRef.current !== reqId) return;
      setSummary(data);
      setSummaryLoaded(true);
      setSummaryError("");
    } catch (err) {
      if (requestRef.current !== reqId) return;
      setSummary(null);
      setSummaryLoaded(false);
      setSummaryError(err.message || "Unable to load security data.");
    }
  }, []);

  const loadAssets = useCallback(
    async (projectId, page, searchVal, typeVal, statusVal, reqId) => {
      setAssetsLoading(true);
      setAssetsError("");
      try {
        const query = { page, page_size: assetsPageSize };
        if (searchVal) query.search = searchVal;
        if (typeVal) query.asset_type = typeVal;
        if (statusVal) query.status = statusVal;
        const data = await listProjectAssets(projectId, query);
        if (requestRef.current !== reqId) return;
        const items = Array.isArray(data) ? data : data.items || [];
        const total = Array.isArray(data) ? items.length : data.total ?? items.length;
        const totalPages = Array.isArray(data) ? 1 : data.total_pages ?? Math.ceil(total / assetsPageSize);
        setAssets(items);
        setAssetsTotal(total);
        setAssetsTotalPages(totalPages);
      } catch (err) {
        if (requestRef.current !== reqId) return;
        setAssets([]);
        setAssetsError(err.message || "Unable to load security data.");
      } finally {
        if (requestRef.current === reqId) setAssetsLoading(false);
      }
    },
    [assetsPageSize]
  );

  const loadRelationships = useCallback(async (projectId, reqId, page, typeFilter) => {
    setRelLoading(true);
    setRelError("");
    try {
      const { listAssetRelationships } = await import("@/lib/api/assets");
      // Backend supports limit, not page; emulate pagination via limit+offset client-side for now
      // For S6.4 we fetch with limit 100 and slice
      const data = await listAssetRelationships({ project_id: projectId, limit: 100 });
      if (requestRef.current !== reqId) return;
      const all = Array.isArray(data) ? data : data.items || data || [];
      const filtered = typeFilter ? all.filter((r) => r.relationship_type === typeFilter || r.relationshipType === typeFilter) : all;
      const total = filtered.length;
      const tp = Math.max(1, Math.ceil(total / relPageSize));
      const offset = (page - 1) * relPageSize;
      const items = filtered.slice(offset, offset + relPageSize);
      setRelationships(items);
      setRelTotal(total);
      setRelTotalPages(tp);
    } catch (err) {
      if (requestRef.current !== reqId) return;
      setRelationships([]);
      setRelError(err.message || "Unable to load security data.");
    } finally {
      if (requestRef.current === reqId) setRelLoading(false);
    }
  }, [relPageSize]);

  const loadAttackPaths = useCallback(async (projectId, reqId) => {
    setAttackLoading(true);
    setAttackError("");
    try {
      const data = await getProjectAttackPaths(projectId, { max_paths: 100, max_depth: 5 });
      if (requestRef.current !== reqId) return;
      setAttackData(data || { paths: [], total: 0, truncated: false });
    } catch (err) {
      if (requestRef.current !== reqId) return;
      setAttackData({ paths: [], total: 0, truncated: false });
      setAttackError(err.message || "Unable to load security data.");
    } finally {
      if (requestRef.current === reqId) setAttackLoading(false);
    }
  }, []);

  const loadFindings = useCallback(async (projectId, reqId) => {
    try {
      const data = await listProjectFindings(projectId, { page: 1, page_size: 20 });
      if (requestRef.current !== reqId) return;
      const items = Array.isArray(data) ? data : data.items || [];
      const total = Array.isArray(data) ? items.length : data.total ?? items.length;
      setFindings(items);
      setFindingsTotal(total);
      setFindingsLoaded(true);
      setFindingsError("");
    } catch (err) {
      if (requestRef.current !== reqId) return;
      setFindings([]);
      setFindingsTotal(0);
      setFindingsLoaded(false);
      setFindingsError(err.message || "Unable to load security data.");
    }
  }, []);

  const reloadAll = useCallback(async () => {
    if (!selectedProjectId || projectStatus !== "ready") return;
    const reqId = requestRef.current + 1;
    requestRef.current = reqId;
    setSelectedPathId(null);
    await Promise.all([
      loadSummary(selectedProjectId, reqId),
      loadAssets(selectedProjectId, assetsPage, debouncedSearch, assetType, assetStatus, reqId),
      loadRelationships(selectedProjectId, reqId, relPage, relTypeFilter),
      loadAttackPaths(selectedProjectId, reqId),
      loadFindings(selectedProjectId, reqId),
    ]);
  }, [selectedProjectId, projectStatus, assetsPage, debouncedSearch, assetType, assetStatus, relPage, relTypeFilter, loadSummary, loadAssets, loadRelationships, loadAttackPaths, loadFindings]);

  useEffect(() => {
    if (projectStatus !== "ready") return undefined;
    const id = window.setTimeout(() => {
      reloadAll();
    }, 0);
    return () => window.clearTimeout(id);
  }, [projectStatus, selectedProjectId, assetsPage, debouncedSearch, assetType, assetStatus, relPage, relTypeFilter, reloadAll]);

  // Clear stale state on project change
  useEffect(() => {
    setSelectedPathId(null);
  }, [selectedProjectId]);

  const filteredPaths = useMemo(() => {
    const all = attackData.paths || [];
    if (!priorityFilter) return all;
    return all.filter((p) => String(p.priority).toLowerCase() === priorityFilter);
  }, [attackData.paths, priorityFilter]);

  const selectedPath = useMemo(
    () => (filteredPaths || []).find((p) => p.path_id === selectedPathId) || null,
    [filteredPaths, selectedPathId]
  );

  if (projectStatus === "loading") {
    return (
      <div>
        <PageHeader title="Attack Surface" description="Project-level view of discovered assets, exposure, relationships, findings, and attack paths." />
        <SkeletonCards count={4} />
      </div>
    );
  }
  if (projectStatus === "error") {
    return (
      <div>
        <PageHeader title="Attack Surface" description="Project-level view of discovered assets, exposure, relationships, findings, and attack paths." />
        <ErrorState title="Unable to load security data." message={projectError} />
      </div>
    );
  }
  if (!selectedProjectId) {
    return (
      <div>
        <PageHeader title="Attack Surface" description="Project-level view of discovered assets, exposure, relationships, findings, and attack paths." />
        <EmptyState title="No projects yet." description="Create a project to explore the attack surface." action={<Link href="/projects" className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">Create Project</Link>} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Surface"
        description="Project-level view of discovered assets, exposure, relationships, findings, and attack paths. All data is derived from backend security intelligence without client-side risk recalculation."
        actions={
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Project</span>
            <ProjectSelect id="attack-surface-project-context" />
          </label>
        }
      />

      {/* Summary */}
      {summaryLoaded ? (
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6" aria-label="Attack surface summary">
          <StatCard label="Total Assets" value={summary?.total_assets ?? 0} />
          <StatCard label="Internet-Facing" value={summary?.internet_facing_assets ?? 0} />
          <StatCard label="With Findings" value={summary?.vulnerable_assets ?? 0} />
          <StatCard label="Critical" value={summary?.critical_assets ?? 0} />
          <StatCard label="Attack Paths" value={attackData.total ?? 0} hint={attackData.truncated ? "Truncated" : undefined} />
          <StatCard label="High/Critical Priority" value={`${summary?.critical_assets ?? 0}/${summary?.high_assets ?? 0}`} hint={summary?.highest_contextual_priority ? `Highest: ${summary.highest_contextual_priority}` : "Not available"} />
        </section>
      ) : summaryError ? (
        <ErrorState title="Unable to load security data." message={summaryError} onRetry={() => loadSummary(selectedProjectId, requestRef.current + 1)} />
      ) : (
        <SkeletonCards count={6} />
      )}

      {/* Internet-facing assets + Relationships */}
      <div className="grid gap-4 xl:grid-cols-2">
        <DashboardSection title="Internet-Facing Assets" action={<Link href="/assets" className="text-xs font-medium text-primary hover:underline">View assets</Link>}>
          {assetsLoading ? (
            <SkeletonTable rows={5} />
          ) : assetsError ? (
            <ErrorState title="Unable to load security data." message={assetsError} onRetry={() => loadAssets(selectedProjectId, assetsPage, debouncedSearch, assetType, assetStatus, requestRef.current + 1)} />
          ) : assets.length === 0 ? (
            <EmptyState
              title="No assets"
              description="No assets match filters. The precise internet-facing classification is available in Asset Intelligence detail; this table shows project assets without assuming exposure from hostname alone."
              action={<Link href="/assets" className="text-xs font-medium text-primary hover:underline">Open Asset Intelligence</Link>}
            />
          ) : (
            <>
              <DataTable
                rowKey={(r) => r.id}
                columns={[
                  { key: "asset_type", header: "Type", render: (r) => <span className="text-xs font-medium">{formatAssetType(r.asset_type)}</span> },
                  { key: "value", header: "Value", render: (r) => <Link href={`/assets/${r.id}`} className="text-xs hover:underline break-all">{r.value}</Link> },
                  { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
                  { key: "last_seen_at", header: "Last seen", render: (r) => <span className="text-xs">{formatWhen(r.last_seen_at)}</span> },
                ]}
                rows={assets.slice(0, 8)}
              />
              <p className="mt-2 text-xs text-muted">
                Showing {assets.length} of {assetsTotal} assets. For definitive exposure, open asset detail — exposure is not inferred from name alone.
              </p>
              <div className="mt-3 flex items-center justify-between">
                <button disabled={assetsPage <= 1} onClick={() => setAssetsPage((p) => Math.max(1, p - 1))} className="rounded-sm border border-border px-3 py-1.5 text-xs disabled:opacity-50">Previous</button>
                <span className="text-xs text-muted">Page {assetsPage} of {assetsTotalPages || 1}</span>
                <button disabled={assetsPage >= assetsTotalPages} onClick={() => setAssetsPage((p) => p + 1)} className="rounded-sm border border-border px-3 py-1.5 text-xs disabled:opacity-50">Next</button>
              </div>
            </>
          )}
        </DashboardSection>

        <DashboardSection title="Asset Relationships" action={<span className="text-xs text-muted">{relTotal} total</span>}>
          <FilterBar>
            <select value={relTypeFilter} onChange={(e) => { setRelTypeFilter(e.target.value); setRelPage(1); }} className="rounded-sm border border-border bg-canvas px-3 py-2 text-xs" aria-label="Filter by relationship type">
              {REL_TYPE_OPTIONS.map((t) => (
                <option key={t || "all"} value={t}>{t || "All types"}</option>
              ))}
            </select>
          </FilterBar>
          {relLoading ? (
            <SkeletonTable rows={5} />
          ) : relError ? (
            <ErrorState title="Unable to load security data." message={relError} />
          ) : relationships.length === 0 ? (
            <EmptyState title="No relationships" description="No relationships discovered for this project or filter." />
          ) : (
            <>
              <div className="space-y-2">
                {relationships.map((rel) => (
                  <div key={rel.id || `${rel.source_asset_id}-${rel.target_asset_id}-${rel.relationship_type}`} className="rounded-sm border border-border bg-canvas px-3 py-2">
                    <p className="break-all text-xs font-medium">
                      <span className="text-muted">{rel.source_asset_id}</span> <span className="mx-1 text-primary">→ {rel.relationship_type} →</span> <span className="text-muted">{rel.target_asset_id}</span>
                    </p>
                    {rel.metadata && Object.keys(rel.metadata).length > 0 && (
                      <pre className="mt-1 max-h-20 overflow-auto whitespace-pre-wrap break-words text-xs text-muted">{JSON.stringify(rel.metadata, null, 2)}</pre>
                    )}
                  </div>
                ))}
              </div>
              <div className="mt-3 flex items-center justify-between">
                <button disabled={relPage <= 1} onClick={() => setRelPage((p) => Math.max(1, p - 1))} className="rounded-sm border border-border px-3 py-1.5 text-xs disabled:opacity-50">Previous</button>
                <span className="text-xs text-muted">Page {relPage} of {relTotalPages || 1} — {relTotal} total</span>
                <button disabled={relPage >= relTotalPages} onClick={() => setRelPage((p) => p + 1)} className="rounded-sm border border-border px-3 py-1.5 text-xs disabled:opacity-50">Next</button>
              </div>
            </>
          )}
        </DashboardSection>
      </div>

      {/* Attack Paths */}
      <DashboardSection
        title="Attack Paths"
        action={
          <div className="flex items-center gap-2">
            <select value={priorityFilter} onChange={(e) => setPriorityFilter(e.target.value)} className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-xs" aria-label="Filter by priority">
              {PRIORITY_OPTIONS.map((p) => (
                <option key={p || "all"} value={p}>{p || "All priorities"}</option>
              ))}
            </select>
            <span className="text-xs text-muted">{filteredPaths.length} / {attackData.total} paths</span>
          </div>
        }
      >
        {attackLoading ? (
          <SkeletonTable rows={4} />
        ) : attackError ? (
          <ErrorState title="Unable to load security data." message={attackError} />
        ) : filteredPaths.length === 0 ? (
          <EmptyState
            title={attackData.total === 0 ? "No attack paths" : "No matching paths"}
            description={
              attackData.total === 0
                ? "No attack paths detected. This is expected when no internet-facing assets are linked to vulnerable assets via relationships."
                : "No paths match the selected priority filter."
            }
            action={attackData.total === 0 ? <Link href="/assets" className="text-xs text-primary hover:underline">View assets</Link> : null}
          />
        ) : (
          <div className="grid gap-4 xl:grid-cols-5">
            <div className="xl:col-span-2 space-y-2">
              {filteredPaths.slice(0, 20).map((p) => (
                <button
                  key={p.path_id}
                  type="button"
                  onClick={() => setSelectedPathId(p.path_id)}
                  className={`w-full rounded-sm border px-3 py-2 text-left ${selectedPathId === p.path_id ? "border-primary bg-surface-hover" : "border-border bg-canvas hover:bg-surface-hover"}`}
                >
                  <p className="flex flex-wrap gap-2 text-xs">
                    <span className={`rounded-sm border px-1.5 py-0.5 ${p.priority === "critical" ? "border-critical text-critical" : p.priority === "high" ? "border-high text-high" : "border-border"}`}>
                      Priority: {p.priority}
                    </span>
                    <span className="rounded-sm border border-border px-1.5 py-0.5">Confidence: {p.confidence}</span>
                    <span className="rounded-sm border border-border px-1.5 py-0.5">Length: {p.length}</span>
                  </p>
                  <p className="mt-1 break-all text-xs font-medium">{p.entry_asset_id} → {p.target_asset_id}</p>
                  <p className="mt-1 line-clamp-2 text-xs text-muted">{p.explanation}</p>
                </button>
              ))}
            </div>

            <div className="xl:col-span-3">
              {!selectedPath ? (
                <div className="rounded-md border border-dashed border-border bg-surface p-6 text-center">
                  <p className="text-sm font-medium">Select a path</p>
                  <p className="mt-1 text-xs text-muted">Choose an attack path to inspect its ordered nodes, relationships, and findings. Backend priority/score/grade are displayed verbatim.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="rounded-md border border-border bg-canvas p-4">
                    <h4 className="text-sm font-semibold">Path overview</h4>
                    <dl className="mt-3 grid grid-cols-2 gap-3 text-xs">
                      <div><dt className="text-muted">Priority</dt><dd className="font-semibold">{selectedPath.priority}</dd></div>
                      <div><dt className="text-muted">Confidence</dt><dd>{selectedPath.confidence}</dd></div>
                      <div><dt className="text-muted">Length</dt><dd>{selectedPath.length}</dd></div>
                      <div><dt className="text-muted">Entry type</dt><dd>{selectedPath.entry_type}</dd></div>
                      <div><dt className="text-muted">Target type</dt><dd>{selectedPath.target_type}</dd></div>
                      <div><dt className="text-muted">Target contextual</dt><dd>{selectedPath.target_contextual_priority || "Not available"}</dd></div>
                    </dl>
                    <p className="mt-3 text-xs text-muted">{selectedPath.explanation}</p>
                    {selectedPath.target_risk_factors?.length ? (
                      <ul className="mt-2 space-y-1">
                        {selectedPath.target_risk_factors.map((f) => (
                          <li key={f.code} className="text-xs"><span className="font-medium">{f.code}</span> — {f.description}</li>
                        ))}
                      </ul>
                    ) : null}
                  </div>

                  {/* Structured visualization */}
                  <div className="rounded-md border border-border bg-surface p-4">
                    <h4 className="text-sm font-semibold">Structured path</h4>
                    <p className="mt-1 text-xs text-muted">Entry → relationships → target (lightweight pre-graph visualization)</p>
                    <div className="mt-4 flex flex-col items-center gap-1">
                      {(() => {
                        const nodes = selectedPath.asset_ids || [];
                        const rels = selectedPath.relationships || [];
                        const elements = [];
                        for (let i = 0; i < nodes.length; i++) {
                          const isEntry = i === 0;
                          const isTarget = i === nodes.length - 1;
                          elements.push(
                            <div key={`node-${i}`} className={`w-full max-w-md rounded-sm border px-3 py-2 text-center ${isEntry ? "border-info bg-info/10" : isTarget ? "border-critical bg-critical/10" : "border-border bg-canvas"}`}>
                              <p className="text-xs font-medium break-all">{nodes[i]}</p>
                              <p className="text-xs text-muted">{isEntry ? "Entry" : isTarget ? "Target" : `Hop ${i}`}</p>
                            </div>
                          );
                          if (i < rels.length) {
                            const rel = rels[i];
                            const rtype = rel.relationship_type || rel.type || "related";
                            elements.push(
                              <div key={`rel-${i}`} className="flex flex-col items-center">
                                <span className="text-primary">↓</span>
                                <span className="rounded-sm border border-border bg-canvas px-2 py-0.5 text-xs">{rtype}</span>
                                <span className="text-primary">↓</span>
                              </div>
                            );
                          }
                        }
                        return elements;
                      })()}
                    </div>
                  </div>

                  <div className="rounded-md border border-border bg-canvas p-4">
                    <h4 className="text-xs font-semibold">Evidence</h4>
                    <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                      <div><dt className="text-muted">Relationship types</dt><dd>{(selectedPath.evidence?.relationship_types || []).join(", ") || "Not available"}</dd></div>
                      <div><dt className="text-muted">Relationship count</dt><dd>{selectedPath.evidence?.relationship_count ?? "Not available"}</dd></div>
                      <div><dt className="text-muted">Asset count</dt><dd>{selectedPath.evidence?.asset_count ?? "Not available"}</dd></div>
                    </dl>
                    {selectedPath.flags && (
                      <p className="mt-2 text-xs text-muted">Flags: {Object.entries(selectedPath.flags).filter(([, v]) => v).map(([k]) => k).join(", ") || "None"}</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </DashboardSection>

      {/* Filters for attack surface */}
      <FilterBar>
        <SearchInput value={search} onChange={setSearch} placeholder="Search assets" id="attack-surface-search" label="Search" />
        <select value={assetType} onChange={(e) => setAssetType(e.target.value)} className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm" aria-label="Filter by asset type">
          {ASSET_TYPE_OPTIONS.map((t) => (
            <option key={t || "all"} value={t}>{t ? formatAssetType(t) : "All asset types"}</option>
          ))}
        </select>
        <select value={assetStatus} onChange={(e) => setAssetStatus(e.target.value)} className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm" aria-label="Filter by asset status">
          {STATUS_OPTIONS.map((s) => (
            <option key={s || "all"} value={s}>{s || "All statuses"}</option>
          ))}
        </select>
        {(assetType || assetStatus || search) && (
          <button type="button" onClick={() => { setSearch(""); setAssetType(""); setAssetStatus(""); }} className="rounded-sm border border-border px-3 py-1.5 text-sm">Clear</button>
        )}
      </FilterBar>

      {/* Findings related to attack surface */}
      <DashboardSection title="Findings related to attack surface" action={<Link href="/findings" className="text-xs font-medium text-primary hover:underline">View findings</Link>}>
        {!findingsLoaded && findingsError ? (
          <ErrorState title="Unable to load security data." message={findingsError} />
        ) : findings.length === 0 ? (
          <EmptyState title="No findings" description="No findings for this project." />
        ) : (
          <DataTable
            rowKey={(r) => r.id}
            columns={[
              { key: "severity", header: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
              { key: "title", header: "Title", render: (r) => <Link href={`/findings/${r.id}`} className="text-xs hover:underline">{r.title}</Link> },
              { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
              { key: "scanner", header: "Scanner" },
              { key: "score", header: "Score", render: (r) => (r.score ?? "—") },
              { key: "asset_id", header: "Asset", render: (r) => <Link href={r.asset_id ? `/assets/${r.asset_id}` : "#"} className="text-xs hover:underline break-all">{r.asset_id || "—"}</Link> },
            ]}
            rows={findings.slice(0, 10)}
          />
        )}
        {findingsTotal > 10 && <p className="mt-2 text-xs text-muted">Showing 10 of {findingsTotal} findings.</p>}
      </DashboardSection>
    </div>
  );
}
