"use client";

/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with stale guards */
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { apiFetch, API_BASE_URL as API_URL } from "@/lib/api/client";
import { listProjectScans } from "@/lib/api/scans";
import { useProjectContext } from "@/lib/project-context";
import PageHeader from "@/components/ui/PageHeader";
import ProjectSelect from "@/components/layout/ProjectSelect";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import FilterBar from "@/components/ui/FilterBar";
import SearchInput from "@/components/ui/SearchInput";
import StatusBadge from "@/components/ui/StatusBadge";
import StatCard from "@/components/ui/StatCard";
import { SkeletonCards, SkeletonTable } from "@/components/ui/Skeleton";

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

function ScansPage() {
  const searchParams = useSearchParams();
  const queryProjectId = searchParams.get("project_id") || "";
  const queryTargetId = searchParams.get("target_id") || "";
  const { selectedProjectId, selectedProject, status: projectStatus, error: projectError, setSelectedProjectId } = useProjectContext();

  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [statusFilter, setStatusFilter] = useState("");
  const [profileFilter, setProfileFilter] = useState("");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");

  // Targets & creation (preserve existing flow)
  const [targets, setTargets] = useState([]);
  const [targetsLoading, setTargetsLoading] = useState(true);
  const [targetsError, setTargetsError] = useState("");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedProfile, setSelectedProfile] = useState("quick");
  const [starting, setStarting] = useState(false);

  const requestRef = useRef(0);

  useEffect(() => {
    const id = window.setTimeout(() => setDebouncedSearch(search.trim().toLowerCase()), 300);
    return () => window.clearTimeout(id);
  }, [search]);

  useEffect(() => {
    if (queryProjectId) setSelectedProjectId(queryProjectId);
  }, [queryProjectId, setSelectedProjectId]);

  useEffect(() => {
    setPage(1);
  }, [selectedProjectId, debouncedSearch, statusFilter, profileFilter]);

  const loadTargets = useCallback(async () => {
    try {
      setTargetsError("");
      const response = await apiFetch(`${API_URL}/api/v1/targets`, { cache: "no-store" });
      if (!response.ok) {
        const err = await response.json().catch(() => null);
        throw new Error(err?.detail || "Failed to load targets");
      }
      const result = await response.json();
      const list = Array.isArray(result) ? result : [];
      // Project-isolation: only consider targets belonging to current project
      const effectiveProject = queryProjectId || selectedProjectId;
      const scopedList = effectiveProject ? list.filter((t) => t.project_id === effectiveProject) : list;
      setTargets(list);
      // Only honor queryTargetId if it belongs to the current project
      const matched = scopedList.find((t) => t.id === queryTargetId);
      if (matched) setSelectedTarget(matched.id);
      else if (scopedList.length > 0) {
        setSelectedTarget((cur) => (cur && scopedList.some((t) => t.id === cur) ? cur : scopedList[0].id));
      } else {
        setSelectedTarget("");
      }
    } catch (err) {
      setTargetsError(err.message || "Failed to load targets");
    } finally {
      setTargetsLoading(false);
    }
  }, [queryTargetId, queryProjectId, selectedProjectId]);

  const loadScans = useCallback(
    async (projectId, p, statusVal, profileVal) => {
      if (!projectId) {
        setScans([]);
        setTotal(0);
        setTotalPages(0);
        setLoading(false);
        return;
      }
      const reqId = requestRef.current + 1;
      requestRef.current = reqId;
      setLoading(true);
      setError("");
      try {
        const query = { page: p, page_size: pageSize };
        if (statusVal) query.status = statusVal;
        if (profileVal) query.profile = profileVal;
        const data = await listProjectScans(projectId, query);
        if (requestRef.current !== reqId) return;
        const items = Array.isArray(data) ? data : data.items || [];
        const t = Array.isArray(data) ? items.length : data.total ?? items.length;
        const tp = Array.isArray(data) ? 1 : data.total_pages ?? Math.ceil(t / pageSize);
        // Client-side search on target value (backend not supporting search for scans)
        let filtered = items;
        if (debouncedSearch) {
          filtered = items.filter((s) => {
            const hay = `${s.target || s.target_id || ""} ${s.profile || ""} ${s.status || ""}`.toLowerCase();
            return hay.includes(debouncedSearch);
          });
        }
        setScans(filtered);
        // For search, total remains server total; filtered length may differ
        setTotal(t);
        setTotalPages(tp);
      } catch (err) {
        if (requestRef.current !== reqId) return;
        setError(err.message || "Unable to load security data.");
      } finally {
        if (requestRef.current === reqId) setLoading(false);
      }
    },
    [pageSize, debouncedSearch]
  );

  useEffect(() => {
    const id = window.setTimeout(() => { loadTargets(); }, 0);
    return () => window.clearTimeout(id);
  }, [loadTargets]);

  useEffect(() => {
    if (projectStatus !== "ready") return undefined;
    const id = window.setTimeout(() => {
      loadScans(selectedProjectId, page, statusFilter, profileFilter);
    }, 0);
    return () => window.clearTimeout(id);
  }, [projectStatus, selectedProjectId, page, statusFilter, profileFilter, loadScans]);

  // Poll running scans
  useEffect(() => {
    const hasActive = scans.some((s) => s.status === "queued" || s.status === "running");
    if (!hasActive || !selectedProjectId) return undefined;
    const interval = setInterval(() => {
      loadScans(selectedProjectId, page, statusFilter, profileFilter);
    }, 3000);
    return () => clearInterval(interval);
  }, [scans, selectedProjectId, page, statusFilter, profileFilter, loadScans]);

  async function startScan(event) {
    event.preventDefault();
    if (!selectedTarget) {
      setError("Please select a target.");
      return;
    }
    if (!selectedProfile) {
      setError("Please select a scan profile.");
      return;
    }
    try {
      setStarting(true);
      setError("");
      const response = await apiFetch(`${API_URL}/api/v1/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_id: selectedTarget, profile: selectedProfile }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => null);
        throw new Error(err?.detail || "Failed to start scan");
      }
      await response.json();
      await loadScans(selectedProjectId, page, statusFilter, profileFilter);
    } catch (err) {
      setError(err.message || "Failed to start scan");
    } finally {
      setStarting(false);
    }
  }

  const targetMap = useMemo(() => {
    const m = {};
    for (const t of targets) m[t.id] = t;
    return m;
  }, [targets]);

  function getTargetValue(id) {
    return targetMap[id]?.value || id;
  }

  const summary = useMemo(() => {
    const totalScans = total;
    const running = scans.filter((s) => s.status === "running").length;
    const queued = scans.filter((s) => s.status === "queued").length;
    const completed = scans.filter((s) => s.status === "completed").length;
    const failed = scans.filter((s) => s.status === "failed").length;
    const partial = scans.filter((s) => s.status === "completed" && s.phase && String(s.phase).includes("partial")).length;
    return { total: totalScans, running, queued, completed, failed, partial };
  }, [scans, total]);

  const runningScans = useMemo(() => scans.filter((s) => s.status === "running" || s.status === "queued"), [scans]);

  if (projectStatus === "loading") {
    return (
      <div className="mx-auto max-w-7xl px-6 py-10">
        <div className="flex min-h-[60vh] items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-white" />
        </div>
      </div>
    );
  }

  if (projectStatus === "error") {
    return (
      <div className="mx-auto max-w-7xl px-6 py-10">
        <ErrorState title="Unable to load security data." message={projectError} />
      </div>
    );
  }

  return (
    <div>
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h1 className="text-2xl font-bold">Scan Operations</h1>
              <p className="mt-1 text-sm text-slate-400">Monitor project scans, scanner execution, progress, failures, retries, and results.</p>
              {selectedProject ? <p className="mt-1 text-xs text-muted">Project: {selectedProject.name}</p> : null}
            </div>
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-2 text-sm">
                <span className="text-muted">Project</span>
                <ProjectSelect id="scans-project-context" />
              </label>
              <Link href="/dashboard" className="text-sm text-slate-400 hover:text-white">← Dashboard</Link>
            </div>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        {error && (
          <div className="mb-6 rounded-xl border border-red-900 bg-red-950/30 p-4">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}
        {targetsError && (
          <div className="mb-6 rounded-xl border border-red-900 bg-red-950/30 p-4">
            <p className="text-sm text-red-400">{targetsError}</p>
          </div>
        )}

        {/* Summary */}
        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
          <StatCard label="Total Scans" value={summary.total} />
          <StatCard label="Running" value={summary.running} />
          <StatCard label="Queued" value={summary.queued} />
          <StatCard label="Completed" value={summary.completed} />
          <StatCard label="Failed" value={summary.failed} />
          <StatCard label="Partial" value={summary.partial ?? "Not available"} />
        </section>

        {/* Start Scan (preserve) */}
        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <div className="mb-6">
            <h2 className="text-lg font-semibold">Start New Scan</h2>
            <p className="mt-1 text-sm text-slate-400">Select a target and scan profile.</p>
          </div>
          <form onSubmit={startScan} className="grid gap-4 lg:grid-cols-[1fr_1fr_auto]">
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Target</label>
              <select
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                disabled={targetsLoading}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
              >
                <option value="">{targetsLoading ? "Loading targets..." : "Select target"}</option>
                {(selectedProjectId ? targets.filter((t) => t.project_id === selectedProjectId) : targets).map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.value} {target.target_type ? `(${target.target_type})` : ""}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Scan Profile</label>
              <select
                value={selectedProfile}
                onChange={(e) => setSelectedProfile(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
              >
                <option value="quick">Quick Scan</option>
                <option value="web">Web Scan</option>
                <option value="full">Full Scan</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                disabled={starting || !selectedTarget}
                className="w-full rounded-lg bg-white px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50 lg:w-auto"
              >
                {starting ? "Starting..." : "Start Scan"}
              </button>
            </div>
          </form>
        </section>

        {/* Running scans prominent */}
        {runningScans.length > 0 && (
          <section className="mb-8 rounded-xl border border-blue-900 bg-blue-950/20 p-6">
            <h2 className="text-lg font-semibold text-blue-300">Running Scans</h2>
            <p className="mt-1 text-sm text-blue-200/70">Actively monitoring {runningScans.length} running scan(s) — polling every 3s.</p>
            <div className="mt-4 space-y-3">
              {runningScans.map((scan) => (
                <div key={scan.id} className="rounded-lg border border-blue-900 bg-slate-900 p-4">
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <p className="font-medium text-white">{getTargetValue(scan.target_id)}</p>
                      <p className="text-xs text-slate-400">
                        {scan.profile} • {scan.status} • Progress: {scan.progress != null ? `${scan.progress}%` : "Not available"}
                      </p>
                    </div>
                    <Link href={`/scans/${scan.id}`} className="inline-flex rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800">
                      View details →
                    </Link>
                  </div>
                  {scan.progress != null && (
                    <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
                      <div className="h-full bg-blue-500 transition-all" style={{ width: `${Math.max(0, Math.min(100, scan.progress))}%` }} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Filters */}
        <section className="mb-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="grid gap-4 lg:grid-cols-[1fr_180px_180px_auto]">
            <SearchInput value={search} onChange={setSearch} placeholder="Search target, profile, status..." id="scans-search" label="Search scans" />
            <div>
              <label htmlFor="scan-status" className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">Status</label>
              <select id="scan-status" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none">
                <option value="">All statuses</option>
                <option value="queued">Queued</option>
                <option value="running">Running</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
              </select>
            </div>
            <div>
              <label htmlFor="scan-profile" className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">Profile</label>
              <select id="scan-profile" value={profileFilter} onChange={(e) => setProfileFilter(e.target.value)} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none">
                <option value="">All profiles</option>
                <option value="quick">Quick</option>
                <option value="web">Web</option>
                <option value="full">Full</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="button"
                onClick={() => { setSearch(""); setStatusFilter(""); setProfileFilter(""); }}
                className="w-full rounded-xl border border-slate-700 px-4 py-3 text-sm text-slate-300 hover:bg-slate-800"
              >
                Clear
              </button>
            </div>
          </div>
          <div className="mt-4 text-xs text-slate-500">
            Showing <span className="font-medium text-slate-300">{scans.length}</span> of <span className="font-medium text-slate-300">{total}</span> scans {selectedProject?.name ? `in ${selectedProject.name}` : ""}
          </div>
        </section>

        {/* Scan inventory */}
        <section>
          <div className="mb-5 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Scan Inventory</h2>
            <span className="text-xs text-slate-500">Page {page} of {totalPages || 1}</span>
          </div>

          {!selectedProjectId ? (
            <EmptyState title="No project selected" description="Select a project to view scans." />
          ) : loading ? (
            <SkeletonTable rows={6} />
          ) : error ? (
            <ErrorState title="Unable to load security data." message={error} onRetry={() => loadScans(selectedProjectId, page, statusFilter, profileFilter)} />
          ) : scans.length === 0 ? (
            <EmptyState title="No scans" description="No scans for this project. Start your first scan above." />
          ) : (
            <>
              <DataTable
                rowKey={(row) => row.id}
                columns={[
                  { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
                  { key: "progress", header: "Progress", render: (row) => (row.progress != null ? `${row.progress}%` : "Not available") },
                  { key: "profile", header: "Profile", render: (row) => <span className="capitalize">{row.profile}</span> },
                  { key: "target", header: "Target", render: (row) => <span className="break-all text-sm">{row.target || getTargetValue(row.target_id)}</span> },
                  { key: "created_at", header: "Started", render: (row) => <span className="text-xs">{row.created_at ? new Date(row.created_at).toLocaleString() : "—"}</span> },
                  { key: "findings_count", header: "Findings", render: (row) => <span className="text-sm">{row.findings_count ?? "—"}</span> },
                  { key: "risk", header: "Risk", render: (row) => (row.risk_score != null ? `${row.risk_score}${row.risk_grade ? ` (${row.risk_grade})` : ""}` : "Not available") },
                  { key: "action", header: "Action", render: (row) => <Link href={`/scans/${row.id}`} className="inline-flex rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 hover:border-slate-500 hover:text-white">View</Link> },
                ]}
                rows={scans}
              />
              <div className="mt-4 flex items-center justify-between gap-2">
                <button type="button" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-sm border border-border px-3 py-1.5 text-sm disabled:opacity-50">Previous</button>
                <span className="text-xs text-muted">Page {page} of {totalPages || 1} — {total} total</span>
                <button type="button" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded-sm border border-border px-3 py-1.5 text-sm disabled:opacity-50">Next</button>
              </div>
              <p className="mt-3 text-xs text-muted">
                Findings/assets counts are from scan results; scanner execution details are on the scan detail page. <Link href="/findings" className="text-primary hover:underline">View findings</Link> • <Link href="/assets" className="text-primary hover:underline">View assets</Link>
              </p>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

export default function ScansRoute() {
  return (
    <Suspense fallback={<div className="p-6 text-sm text-slate-400">Loading scans...</div>}>
      <ScansPage />
    </Suspense>
  );
}
