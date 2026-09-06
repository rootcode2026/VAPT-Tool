"use client";

/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with stale guards */
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
import { getProjectSecuritySummary, getProjectAttackPaths } from "@/lib/api/assets";
import { listProjectFindings } from "@/lib/api/findings";
import { useProjectContext } from "@/lib/project-context";
import { SEVERITY_ORDER } from "@/lib/severity";

const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS = ["", "open", "resolved", "false_positive", "accepted", "confirmed", "remediated"];
const VALIDATION_OPTIONS = ["", "detected", "corroborated", "needs_review", "confirmed", "false_positive", "accepted_risk", "remediated", "reopened"];

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

function getValidationState(finding) {
  const meta = finding?.metadata || finding?.extra_data || {};
  return (
    finding?.validation_state ||
    finding?.validationState ||
    meta.validation_state ||
    meta.validationState ||
    meta.state ||
    finding?.state ||
    null
  );
}
function getConfidence(finding) {
  const meta = finding?.metadata || {};
  return {
    score: finding?.confidence_score ?? meta.confidence_score ?? meta.confidenceScore ?? null,
    level: finding?.confidence_level ?? meta.confidence_level ?? meta.confidenceLevel ?? null,
  };
}
function getRisk(finding) {
  const meta = finding?.metadata || {};
  return {
    score: finding?.risk_score ?? meta.risk_score ?? finding?.score ?? null,
    level: finding?.risk_level ?? meta.risk_level ?? null,
    grade: finding?.risk_grade ?? meta.risk_grade ?? null,
  };
}
function getRequiresReview(finding) {
  const meta = finding?.metadata || {};
  return meta.requires_human_review ?? finding?.requires_human_review ?? null;
}
function getEvidenceCount(finding) {
  const meta = finding?.metadata || {};
  if (Array.isArray(meta.evidence_items)) return meta.evidence_items.length;
  if (Array.isArray(finding?.evidence_items)) return finding.evidence_items.length;
  return finding?.evidence ? 1 : 0;
}

export default function FindingsPage() {
  const { selectedProjectId, selectedProject, status: projectStatus, error: projectError } = useProjectContext();

  const [summary, setSummary] = useState(null);
  const [summaryError, setSummaryError] = useState("");
  const [summaryLoaded, setSummaryLoaded] = useState(false);

  const [findings, setFindings] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [scanner, setScanner] = useState("");
  const [validationFilter, setValidationFilter] = useState("");
  const [assignee, setAssignee] = useState("");
  const [tag, setTag] = useState("");
  const [debouncedAssignee, setDebouncedAssignee] = useState("");
  const [debouncedTag, setDebouncedTag] = useState("");

  const [attackPaths, setAttackPaths] = useState([]);
  const [attackError, setAttackError] = useState("");

  const requestRef = useRef(0);

  useEffect(() => {
    const id = window.setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => window.clearTimeout(id);
  }, [search]);

  useEffect(() => {
    const a = window.setTimeout(() => setDebouncedAssignee(assignee.trim()), 300);
    return () => window.clearTimeout(a);
  }, [assignee]);

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedTag(tag.trim().toLowerCase()), 300);
    return () => window.clearTimeout(t);
  }, [tag]);

  useEffect(() => {
    setPage(1);
  }, [selectedProjectId, debouncedSearch, severity, status, scanner, debouncedAssignee, debouncedTag]);

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

  const loadFindings = useCallback(async (projectId, p, searchVal, sev, stat, scan, reqId, assigneeVal, tagVal) => {
    setLoading(true);
    setError("");
    try {
      const query = { page: p, page_size: pageSize };
      if (searchVal) query.search = searchVal;
      if (sev) query.severity = sev;
      if (stat) query.status = stat;
      if (scan) query.scanner = scan;
      if (assigneeVal) query.assigned_to = assigneeVal;
      if (tagVal) query.tag = tagVal;
      const data = await listProjectFindings(projectId, query);
      if (requestRef.current !== reqId) return;
      const items = Array.isArray(data) ? data : data.items || [];
      const t = Array.isArray(data) ? items.length : data.total ?? items.length;
      const tp = Array.isArray(data) ? 1 : data.total_pages ?? Math.ceil(t / pageSize);
      setFindings(items);
      setTotal(t);
      setTotalPages(tp);
    } catch (err) {
      if (requestRef.current !== reqId) return;
      setFindings([]);
      setError(err.message || "Unable to load security data.");
    } finally {
      if (requestRef.current === reqId) setLoading(false);
    }
  }, [pageSize]);

  const loadAttackPaths = useCallback(async (projectId, reqId) => {
    try {
      const data = await getProjectAttackPaths(projectId, { max_paths: 50 });
      if (requestRef.current !== reqId) return;
      setAttackPaths(data?.paths || []);
      setAttackError("");
    } catch (err) {
      if (requestRef.current !== reqId) return;
      setAttackPaths([]);
      setAttackError(err.message || "Unable to load security data.");
    }
  }, []);

  const reloadAll = useCallback(async () => {
    if (!selectedProjectId || projectStatus !== "ready") return;
    const reqId = requestRef.current + 1;
    requestRef.current = reqId;
    await Promise.all([
      loadSummary(selectedProjectId, reqId),
      loadFindings(selectedProjectId, page, debouncedSearch, severity, status, scanner, reqId, debouncedAssignee, debouncedTag),
      loadAttackPaths(selectedProjectId, reqId),
    ]);
  }, [selectedProjectId, projectStatus, page, debouncedSearch, severity, status, scanner, debouncedAssignee, debouncedTag, loadSummary, loadFindings, loadAttackPaths]);

  useEffect(() => {
    if (projectStatus !== "ready") return undefined;
    const id = window.setTimeout(() => { reloadAll(); }, 0);
    return () => window.clearTimeout(id);
  }, [projectStatus, selectedProjectId, page, debouncedSearch, severity, status, scanner, debouncedAssignee, debouncedTag, reloadAll]);

  const scanners = useMemo(() => {
    const s = [...new Set(findings.map((f) => f.scanner).filter(Boolean))].sort();
    return s;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    if (!validationFilter) return findings;
    return findings.filter((f) => {
      const state = String(getValidationState(f) || "").toLowerCase();
      return state === validationFilter;
    });
  }, [findings, validationFilter]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const k = String(f.severity || "").toLowerCase();
      if (k in counts) counts[k] += 1;
      else counts.info += 1;
    }
    return counts;
  }, [findings]);

  const attackPathAssetIds = useMemo(() => new Set(attackPaths.flatMap((p) => p.asset_ids || [])), [attackPaths]);

  if (projectStatus === "loading") {
    return (
      <div>
        <PageHeader title="Findings Intelligence" description="A project-scoped view of discovered, correlated, validated, and risk-prioritized security findings." />
        <SkeletonCards count={4} />
      </div>
    );
  }
  if (projectStatus === "error") {
    return (
      <div>
        <PageHeader title="Findings Intelligence" description="A project-scoped view of discovered, correlated, validated, and risk-prioritized security findings." />
        <ErrorState title="Unable to load security data." message={projectError} />
      </div>
    );
  }
  if (!selectedProjectId) {
    return (
      <div>
        <PageHeader title="Findings Intelligence" description="A project-scoped view of discovered, correlated, validated, and risk-prioritized security findings." />
        <EmptyState title="No projects yet." description="Create a project to view findings." action={<Link href="/projects" className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">Create Project</Link>} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings Intelligence"
        description="A project-scoped view of discovered, correlated, validated, and risk-prioritized security findings."
        actions={
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Project</span>
            <ProjectSelect id="findings-project-context" />
          </label>
        }
      />

      {/* Summary */}
      {summaryLoaded ? (
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-7" aria-label="Findings summary">
          <StatCard label="Total Findings" value={summary?.total_assets !== undefined ? total : total} hint={`${total} total`} />
          <StatCard label="Critical" value={summary?.critical_assets ?? severityCounts.critical} />
          <StatCard label="High" value={summary?.high_assets ?? severityCounts.high} />
          <StatCard label="Medium" value={summary?.medium_assets ?? severityCounts.medium} />
          <StatCard label="Low" value={summary?.low_assets ?? severityCounts.low} />
          <StatCard label="Vulnerable Assets" value={summary?.vulnerable_assets ?? 0} />
          <StatCard label="Attack Paths" value={summary?.attack_path_count ?? attackPaths.length} hint={summary?.highest_contextual_priority ? `Highest: ${summary.highest_contextual_priority}` : undefined} />
        </section>
      ) : summaryError ? (
        <ErrorState title="Unable to load security data." message={summaryError} />
      ) : (
        <SkeletonCards count={7} />
      )}

      {/* Search + Filters */}
      <FilterBar>
        <SearchInput value={search} onChange={setSearch} placeholder="Search title, CVE, scanner..." id="findings-search" label="Search findings" />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm" aria-label="Filter by severity">
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.slice(1).map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm" aria-label="Filter by status">
          <option value="">All statuses</option>
          {STATUS_OPTIONS.slice(1).map((s) => (
            <option key={s} value={s}>{s.replaceAll("_", " ")}</option>
          ))}
        </select>
        <select value={scanner} onChange={(e) => setScanner(e.target.value)} className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm" aria-label="Filter by scanner">
          <option value="">All scanners</option>
          {scanners.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select value={validationFilter} onChange={(e) => setValidationFilter(e.target.value)} className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm" aria-label="Filter by validation">
          {VALIDATION_OPTIONS.map((v) => (
            <option key={v || "all"} value={v}>{v ? v.replaceAll("_", " ") : "All validation"}</option>
          ))}
        </select>
        <input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="Assignee UUID" aria-label="Filter by assignee" className="rounded-sm border border-border bg-canvas px-3 py-2 font-mono text-sm" />
        <input value={tag} onChange={(e) => setTag(e.target.value)} placeholder="Tag" aria-label="Filter by tag" className="rounded-sm border border-border bg-canvas px-3 py-2 text-sm" />
        {(severity || status || scanner || validationFilter || debouncedSearch || assignee || tag) && (
          <button type="button" onClick={() => { setSearch(""); setSeverity(""); setStatus(""); setScanner(""); setValidationFilter(""); setAssignee(""); setTag(""); }} className="rounded-sm border border-border px-3 py-1.5 text-sm hover:bg-surface-hover">
            Clear
          </button>
        )}
        <span className="text-xs text-muted">{total} findings {selectedProject?.name ? `in ${selectedProject.name}` : ""}</span>
      </FilterBar>

      {/* Inventory */}
      <div className="rounded-md border border-border bg-surface p-4 sm:p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Finding Inventory</h2>
          <span className="text-xs text-muted">Page {page} of {totalPages || 1} — {total} total</span>
        </div>

        {loading ? (
          <SkeletonTable rows={6} />
        ) : error ? (
          <ErrorState title="Unable to load security data." message={error} onRetry={() => loadFindings(selectedProjectId, page, debouncedSearch, severity, status, scanner, requestRef.current + 1)} />
        ) : filteredFindings.length === 0 ? (
          <EmptyState title={findings.length === 0 ? "No findings" : "No matching findings"} description={findings.length === 0 ? "No findings discovered for this project." : "No findings match the current filters."} />
        ) : (
          <>
            <DataTable
              rowKey={(row) => row.id}
              columns={[
                { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
                {
                  key: "title",
                  header: "Title",
                  render: (row) => (
                    <Link href={`/findings/${row.id}`} className="text-sm font-medium hover:underline">
                      {row.title}
                    </Link>
                  ),
                },
                {
                  key: "validation",
                  header: "Validation",
                  render: (row) => {
                    const state = getValidationState(row);
                    if (!state) return <span className="text-xs text-muted">Not available</span>;
                    const requires = getRequiresReview(row);
                    return (
                      <span className="inline-flex flex-col gap-1">
                        <span className="rounded-sm border border-border px-1.5 py-0.5 text-xs">{String(state).replaceAll("_", " ")}</span>
                        {requires === true && <span className="text-xs text-warning">Requires human review</span>}
                        {requires === false && <span className="text-xs text-success">Human validated</span>}
                      </span>
                    );
                  },
                },
                {
                  key: "risk",
                  header: "Risk",
                  render: (row) => {
                    const r = getRisk(row);
                    if (r.score == null) return <span className="text-xs text-muted">Not available</span>;
                    return <span className="text-xs font-medium">{r.score}{r.grade ? ` (${r.grade})` : ""}{r.level ? ` • ${r.level}` : ""}</span>;
                  },
                },
                {
                  key: "confidence",
                  header: "Confidence",
                  render: (row) => {
                    const c = getConfidence(row);
                    if (c.score == null) return <span className="text-xs text-muted">Not available</span>;
                    return <span className="text-xs">{c.score}{c.level ? ` • ${c.level}` : ""}</span>;
                  },
                },
                { key: "asset", header: "Asset", render: (row) => (row.asset_id ? <Link href={`/assets/${row.asset_id}`} className="text-xs hover:underline break-all">{row.asset_id}</Link> : <span className="text-xs text-muted">Not available</span>) },
                { key: "scanner", header: "Scanner", render: (row) => <span className="text-xs">{row.scanner || "—"}</span> },
                { key: "cve", header: "CVE/CWE", render: (row) => <span className="text-xs">{row.cve || row.cwe || "—"}</span> },
                { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
                { key: "assignee", header: "Assignee", render: (row) => (row.assigned_to ? <span className="font-mono text-xs">{String(row.assigned_to).slice(0, 8)}</span> : <span className="text-xs text-muted">—</span>) },
                { key: "created_at", header: "Created", render: (row) => <span className="text-xs">{formatWhen(row.created_at)}</span> },
              ]}
              rows={filteredFindings}
            />
            {/* Attack path context per finding */}
            <div className="mt-3 hidden text-xs text-muted xl:block">
              {attackPaths.length > 0 ? (
                <p>
                  {filteredFindings.filter((f) => f.asset_id && attackPathAssetIds.has(f.asset_id)).length} of {filteredFindings.length} findings on this page are associated with attack-surface assets.{" "}
                  <Link href="/attack-surface" className="text-primary hover:underline">View attack surface</Link>
                </p>
              ) : attackError ? null : (
                <p>No attack paths for this project — findings show as unassociated.</p>
              )}
            </div>
          </>
        )}

        <div className="mt-4 flex items-center justify-between gap-2">
          <button type="button" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-sm border border-border px-3 py-1.5 text-sm disabled:opacity-50">Previous</button>
          <span className="text-xs text-muted">{total} findings • Page {page} of {totalPages || 1}</span>
          <button type="button" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded-sm border border-border px-3 py-1.5 text-sm disabled:opacity-50">Next</button>
        </div>
      </div>

      {/* Additional intelligence strip */}
      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-md border border-border bg-surface p-4">
          <h3 className="text-sm font-semibold">Scanner Provenance</h3>
          <p className="mt-1 text-xs text-muted">Which scanners contributed evidence. Corroboration is visible when backend reports multiple scanners.</p>
          {findings.length === 0 ? (
            <p className="mt-3 text-xs text-muted">Not available</p>
          ) : (
            <ul className="mt-3 flex flex-wrap gap-2">
              {[...new Set(findings.map((f) => f.scanner).filter(Boolean))].map((s) => (
                <li key={s} className="rounded-sm border border-border bg-canvas px-2 py-1 text-xs">{s}</li>
              ))}
            </ul>
          )}
        </div>
        <div className="rounded-md border border-border bg-surface p-4">
          <h3 className="text-sm font-semibold">Human Review Safety</h3>
          <p className="mt-1 text-xs text-muted">Automated detections require human review. Confirmed findings are human validated.</p>
          <ul className="mt-3 space-y-1 text-xs">
            <li><span className="font-medium">Detected/Corroborated</span> — Automated detection. Requires human review.</li>
            <li><span className="font-medium">Needs Review</span> — Flagged for analyst.</li>
            <li><span className="font-medium">Confirmed/False Positive</span> — Human validated.</li>
          </ul>
          <p className="mt-2 text-xs text-warning">Do not label scanner detections as “Verified” or “Confirmed” without human validation.</p>
        </div>
      </div>
    </div>
  );
}
