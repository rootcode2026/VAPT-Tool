"use client";

/* eslint-disable react-hooks/set-state-in-effect -- polling and project guards */
import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { API_BASE_URL as API_URL, apiFetch } from "@/lib/api/client";
import PageHeader from "@/components/ui/PageHeader";
import StatusBadge from "@/components/ui/StatusBadge";
import SeverityBadge from "@/components/ui/SeverityBadge";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import { severityClassName } from "@/lib/severity";

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}
function formatDuration(ms) {
  if (ms == null) return "Not available";
  const n = Number(ms);
  if (Number.isNaN(n)) return "Not available";
  if (n < 1000) return `${n} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}
function formatErrorCategory(v) {
  if (!v) return "Not available";
  return String(v).replaceAll("_", " ");
}

export default function ScanDetailsPage() {
  const params = useParams();
  const scanId = params?.scan_id;

  const [data, setData] = useState(null);
  const [progressData, setProgressData] = useState(null);
  const [progressError, setProgressError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const pollRef = useRef(null);
  const progressRef = useRef(0);

  const loadScanDetails = useCallback(async () => {
    if (!scanId) return null;
    try {
      setError("");
      const response = await apiFetch(`${API_URL}/api/v1/scans/${scanId}/details`, { cache: "no-store" });
      if (!response.ok) {
        const err = await response.json().catch(() => null);
        throw new Error(err?.detail || "Failed to load scan details");
      }
      const result = await response.json();
      setData(result);
      return result;
    } catch (err) {
      setError(err.message || "Failed to load scan details");
      return null;
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  const loadProgress = useCallback(async () => {
    if (!scanId) return;
    const reqId = progressRef.current + 1;
    progressRef.current = reqId;
    try {
      const response = await apiFetch(`${API_URL}/api/v1/scans/${scanId}/progress`, { cache: "no-store" });
      if (!response.ok) {
        const err = await response.json().catch(() => null);
        throw new Error(err?.detail || "Failed to load progress");
      }
      const result = await response.json();
      if (progressRef.current !== reqId) return;
      setProgressData(result);
      setProgressError("");
      return result;
    } catch (err) {
      if (progressRef.current !== reqId) return;
      setProgressError(err.message || "Unable to load progress");
      return null;
    }
  }, [scanId]);

  useEffect(() => {
    loadScanDetails();
  }, [loadScanDetails]);

  useEffect(() => {
    loadProgress();
  }, [loadProgress]);

  // Poll progress only while running
  useEffect(() => {
    const status = (data?.scan?.status || progressData?.status || "").toLowerCase();
    const isRunning = status === "running" || status === "queued";
    if (!isRunning) {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return undefined;
    }
    if (pollRef.current) return undefined;
    pollRef.current = setInterval(() => {
      loadProgress();
      // Also refresh details to get eventual findings count
      // Don't fetch details every poll to avoid N+1, just progress
    }, 3000);
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [data?.scan?.status, progressData?.status, loadProgress]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-blue-500" />
          <h1 className="text-xl font-semibold">Loading scan...</h1>
          <p className="mt-2 text-sm text-slate-400">Fetching scan details</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div>
        <div className="mx-auto max-w-5xl px-6 py-10">
          <Link href="/scans" className="text-sm text-slate-400 hover:text-white">← Back to Scans</Link>
          <div className="mt-8 rounded-xl border border-red-900 bg-red-950/30 p-6">
            <h1 className="text-lg font-semibold text-red-300">Unable to load scan</h1>
            <p className="mt-2 text-sm text-red-400">{error || "Scan not found"}</p>
          </div>
        </div>
      </div>
    );
  }

  const scan = data.scan;
  const findings = data.findings || [];
  const progress = progressData || {};
  const scanners = progress.scanners || scan.scanner_summary || {};
  const scannerEntries = Object.entries(scanners);

  const counts = {
    critical: findings.filter((f) => f.severity?.toLowerCase() === "critical").length,
    high: findings.filter((f) => f.severity?.toLowerCase() === "high").length,
    medium: findings.filter((f) => f.severity?.toLowerCase() === "medium").length,
    low: findings.filter((f) => f.severity?.toLowerCase() === "low").length,
    info: findings.filter((f) => f.severity?.toLowerCase() === "info").length,
  };

  const isRunning = scan.status === "running" || scan.status === "queued";
  const progressPct = progress.progress ?? scan.progress ?? null;
  const startedAt = scan.created_at || progress.started_at || null;
  // completed_at not in scan model, use updated_at fallback via progress? Show Not available if missing
  const completedAt = scan.completed_at || null;

  function statusClasses(status) {
    switch (status?.toLowerCase()) {
      case "completed": return "bg-green-950 text-green-400";
      case "running": return "bg-blue-950 text-blue-400";
      case "queued": return "bg-yellow-950 text-yellow-400";
      case "failed": return "bg-red-950 text-red-400";
      default: return "bg-slate-800 text-slate-400";
    }
  }

  function severityClasses(sev) { return severityClassName(sev); }

  return (
    <div>
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <Link href="/scans" className="text-sm text-slate-400 hover:text-white">← Back to Scans</Link>
              <h1 className="mt-3 text-2xl font-bold">Scan Details</h1>
              <p className="mt-1 text-sm text-slate-400">Security assessment results — monitor execution, retries, and findings.</p>
            </div>
            <span className={`inline-flex w-fit rounded-full px-3 py-1 text-xs font-medium capitalize ${statusClasses(scan.status)}`}>{scan.status}</span>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Scan Overview */}
        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-lg font-semibold">Scan Overview</h2>
          <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Scan ID</p>
              <p className="mt-2 break-all text-sm text-slate-300">{scan.id}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Target</p>
              <p className="mt-2 break-all text-sm text-slate-300">{scan.target_id}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Profile</p>
              <p className="mt-2 text-sm text-slate-300 capitalize">{scan.profile || "—"}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Phase</p>
              <p className="mt-2 text-sm text-slate-300">{scan.phase ? String(scan.phase).replaceAll("_", " ") : "—"}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Status</p>
              <p className="mt-2 text-sm"><StatusBadge status={scan.status} /></p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Progress</p>
              <p className="mt-2 text-sm text-slate-300">{progressPct != null ? `${progressPct}%` : "Not available"}</p>
              {progressPct != null && (
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full bg-blue-500" style={{ width: `${Math.max(0, Math.min(100, progressPct))}%` }} />
                </div>
              )}
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Started</p>
              <p className="mt-2 text-sm text-slate-300">{formatWhen(startedAt)}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Completed</p>
              <p className="mt-2 text-sm text-slate-300">{formatWhen(completedAt)}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Duration</p>
              <p className="mt-2 text-sm text-slate-300">{scan.duration_ms != null ? formatDuration(scan.duration_ms) : "Not available"}</p>
            </div>
          </div>
          {isRunning && (
            <div className="mt-6 rounded-lg border border-blue-900 bg-blue-950/30 px-4 py-3">
              <div className="flex items-center gap-3">
                <div className="h-2 w-2 animate-pulse rounded-full bg-blue-400" />
                <p className="text-sm text-blue-300">Scan is currently in progress. Progress refreshes every 3s and stops at completion.</p>
              </div>
            </div>
          )}
          {progressError && <p className="mt-3 text-xs text-muted">Progress update failed: {progressError} — showing last known state.</p>}
        </section>

        {/* Execution Summary */}
        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-lg font-semibold">Execution Summary</h2>
          <p className="mt-1 text-sm text-slate-400">Per-scanner attempts, duration, retryable failures, and scanner-level findings/assets. Partial failures remain visible even when overall scan is Completed.</p>
          <div className="mt-4 grid gap-4 sm:grid-cols-4">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs text-slate-500">Total Scanners</p>
              <p className="mt-1 text-2xl font-bold text-white">{progress.total_scanners ?? (scannerEntries.length || "—")}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs text-slate-500">Completed</p>
              <p className="mt-1 text-2xl font-bold text-emerald-400">{progress.completed ?? "—"}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs text-slate-500">Failed</p>
              <p className="mt-1 text-2xl font-bold text-red-400">{progress.failed ?? "—"}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs text-slate-500">Running / Pending</p>
              <p className="mt-1 text-2xl font-bold text-blue-400">{progress.running != null ? `${progress.running} / ${progress.pending ?? 0}` : "—"}</p>
            </div>
          </div>
        </section>

        {/* Scanner Execution Table */}
        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-lg font-semibold">Scanner Execution</h2>
          <p className="mt-1 text-sm text-slate-400">One row per scanner attempt. Do not hide failed scanners — partial completion is analyst-relevant.</p>
          {scannerEntries.length === 0 ? (
            <div className="mt-6 rounded-lg border border-dashed border-slate-700 p-8 text-center">
              <p className="text-sm text-slate-400">No execution results.</p>
              <p className="mt-1 text-xs text-slate-500">Scanner results appear once execution begins.</p>
            </div>
          ) : (
            <div className="mt-6">
              <DataTable
                rowKey={(row) => row[0]}
                columns={[
                  { key: "scanner", header: "Scanner", render: (row) => <span className="text-sm font-medium capitalize">{row[0]}</span> },
                  { key: "status", header: "Status", render: (row) => <span className={`inline-flex rounded-full px-2 py-1 text-xs ${row[1]?.status === "failed" ? "bg-red-950 text-red-400" : row[1]?.status === "completed" ? "bg-emerald-950 text-emerald-400" : "bg-slate-800 text-slate-300"}`}>{row[1]?.status || "Not available"}</span> },
                  { key: "attempt", header: "Attempt", render: (row) => <span className="text-sm">{row[1]?.attempt != null ? `${row[1].attempt} / ${row[1]?.max_attempts ?? 2}` : "Not available"}</span> },
                  { key: "duration", header: "Duration", render: (row) => <span className="text-sm">{row[1]?.duration_ms != null ? formatDuration(row[1].duration_ms) : "Not available"}</span> },
                  { key: "findings", header: "Findings", render: (row) => <span className="text-sm">{row[1]?.findings_count ?? "—"}</span> },
                  { key: "assets", header: "Assets", render: (row) => <span className="text-sm">{row[1]?.assets_count ?? "—"}</span> },
                  { key: "retryable", header: "Retryable", render: (row) => <span className="text-xs">{row[1]?.retryable == null ? "Not available" : row[1].retryable ? "Yes" : "No"}</span> },
                  { key: "error", header: "Error", render: (row) => <span className="max-w-[14rem] truncate text-xs text-slate-400" title={row[1]?.error_message || row[1]?.error || ""}>{row[1]?.error_type ? `${row[1].error_type}${row[1]?.error_message ? `: ${row[1].error_message}` : ""}` : "—"}</span> },
                ]}
                rows={scannerEntries}
              />
              {/* Mobile cards fallback via DataTable itself handles */}
            </div>
          )}
        </section>

        {/* Retries */}
        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-lg font-semibold">Retries</h2>
          <p className="mt-1 text-sm text-slate-400">Attempt number and retryable flag per scanner. Observational only — no retry controls in this stage.</p>
          {scannerEntries.length === 0 ? (
            <p className="mt-4 text-sm text-slate-500">Not available</p>
          ) : (
            <ul className="mt-4 space-y-2">
              {scannerEntries.map(([name, info]) => (
                <li key={name} className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-4 py-3 text-sm">
                  <span className="font-medium capitalize">{name}</span>
                  <span className="text-slate-500">Attempt {info?.attempt ?? "—"} / {info?.max_attempts ?? 2}</span>
                  <span className={`rounded-full px-2 py-1 text-xs ${info?.retryable ? "bg-yellow-950 text-yellow-400" : "bg-slate-800 text-slate-400"}`}>
                    Retryable: {info?.retryable == null ? "Not available" : info.retryable ? "Yes" : "No"}
                  </span>
                  {info?.error_type && <span className="text-xs text-slate-500">Error: {formatErrorCategory(info.error_type)}</span>}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Failure Information */}
        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-lg font-semibold">Failure Information</h2>
          <p className="mt-1 text-sm text-slate-400">Taxonomy: timeout, docker_transport, docker_api, container_failure, invalid_target, scanner_failure, parser_failure, persistence_failure, unknown.</p>
          {(() => {
            const failed = scannerEntries.filter(([, info]) => info?.status === "failed" || info?.error_type);
            if (failed.length === 0) return <p className="mt-4 text-sm text-slate-500">No scanner failures for this scan.</p>;
            return (
              <div className="mt-4 space-y-3">
                {failed.map(([name, info]) => (
                  <div key={name} className="rounded-lg border border-red-900 bg-red-950/20 p-4">
                    <p className="text-sm font-medium text-red-300">{name} — {info?.status || "failed"}</p>
                    <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
                      <div><dt className="text-slate-500">Error Type</dt><dd className="mt-1 break-words text-slate-300">{formatErrorCategory(info?.error_type)}</dd></div>
                      <div><dt className="text-slate-500">Error Phase</dt><dd className="mt-1 break-words text-slate-300">{info?.error_phase || "Not available"}</dd></div>
                      <div className="sm:col-span-2"><dt className="text-slate-500">Error Message</dt><dd className="mt-1 break-words text-slate-300">{info?.error_message || info?.error || "Not available"}</dd></div>
                      <div><dt className="text-slate-500">Attempt</dt><dd className="mt-1 text-slate-300">{info?.attempt != null ? `${info.attempt} / ${info?.max_attempts ?? 2}` : "Not available"}</dd></div>
                      <div><dt className="text-slate-500">Retryable</dt><dd className="mt-1 text-slate-300">{info?.retryable == null ? "Not available" : info.retryable ? "Yes" : "No"}</dd></div>
                      <div><dt className="text-slate-500">Duration</dt><dd className="mt-1 text-slate-300">{formatDuration(info?.duration_ms)}</dd></div>
                    </dl>
                  </div>
                ))}
              </div>
            );
          })()}
        </section>

        {/* Risk Assessment (existing) */}
        <section className="mb-8">
          <h2 className="mb-4 text-lg font-semibold">Risk Assessment</h2>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <p className="text-sm text-slate-400">Risk Score</p>
              <p className="mt-2 text-4xl font-bold">{scan.risk_score ?? "—"}</p>
              <p className="mt-2 text-xs text-slate-500">Overall security score</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <p className="text-sm text-slate-400">Risk Grade</p>
              <p className="mt-2 text-4xl font-bold">{scan.risk_grade ?? "—"}</p>
              <p className="mt-2 text-xs text-slate-500">Assessment grade</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <p className="text-sm text-slate-400">Risk Level</p>
              <p className="mt-2 text-2xl font-bold capitalize">{scan.risk_level ?? "—"}</p>
              <p className="mt-2 text-xs text-slate-500">Current risk classification</p>
            </div>
          </div>
        </section>

        {/* Results */}
        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-lg font-semibold">Results</h2>
          <div className="mt-4 grid gap-4 sm:grid-cols-3">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs text-slate-500">Findings Count</p>
              <p className="mt-1 text-2xl font-bold text-white">{findings.length}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs text-slate-500">Scanners</p>
              <p className="mt-1 text-2xl font-bold text-white">{scannerEntries.length || "—"}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs text-slate-500">Assets</p>
              <p className="mt-1 text-2xl font-bold text-white">{progress.assets_count ?? "Not available"}</p>
            </div>
          </div>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/findings" className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">View Findings →</Link>
            <Link href="/assets" className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">View Assets →</Link>
            <Link href="/attack-surface" className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">View Attack Surface →</Link>
          </div>
        </section>

        <section className="mb-8">
          <div className="mb-4">
            <h2 className="text-lg font-semibold">Finding Summary</h2>
            <p className="mt-1 text-sm text-slate-400">{findings.length} total finding{findings.length !== 1 ? "s" : ""}</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5"><p className="text-sm text-slate-400">Critical</p><p className="mt-2 text-3xl font-bold text-red-400">{counts.critical}</p></div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5"><p className="text-sm text-slate-400">High</p><p className="mt-2 text-3xl font-bold text-orange-400">{counts.high}</p></div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5"><p className="text-sm text-slate-400">Medium</p><p className="mt-2 text-3xl font-bold text-yellow-400">{counts.medium}</p></div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5"><p className="text-sm text-slate-400">Low</p><p className="mt-2 text-3xl font-bold text-blue-400">{counts.low}</p></div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5"><p className="text-sm text-slate-400">Info</p><p className="mt-2 text-3xl font-bold text-slate-300">{counts.info}</p></div>
          </div>
        </section>

        <section>
          <div className="mb-4">
            <h2 className="text-lg font-semibold">Findings</h2>
            <p className="mt-1 text-sm text-slate-400">Security issues discovered during this scan.</p>
          </div>
          {findings.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-12 text-center">
              <h3 className="text-lg font-semibold">No findings</h3>
              <p className="mt-2 text-sm text-slate-400">No security findings were detected during this scan.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {findings.map((finding, index) => (
                <article key={finding.id || `${finding.title}-${index}`} className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0">
                      <div className="mb-3 flex flex-wrap items-center gap-2">
                        <span className={`rounded-md px-2.5 py-1 text-xs font-medium uppercase ${finding.scanner === "nmap" ? "bg-purple-950 text-purple-300" : finding.scanner === "nuclei" ? "bg-cyan-950 text-cyan-300" : finding.scanner === "zap" ? "bg-orange-950 text-orange-300" : "bg-slate-800 text-slate-300"}`}>{finding.scanner}</span>
                        <span className={`rounded-md px-2.5 py-1 text-xs font-medium uppercase border ${severityClasses(finding.severity)}`}>{finding.severity}</span>
                        {finding.status && <span className="rounded-md bg-slate-800 px-2.5 py-1 text-xs font-medium capitalize text-slate-400">{finding.status}</span>}
                      </div>
                      <h3 className="text-lg font-semibold">{finding.title}</h3>
                    </div>
                    {finding.score !== null && finding.score !== undefined && (
                      <div className="shrink-0 text-right">
                        <p className="text-xs text-slate-500">Score</p>
                        <p className="text-xl font-bold">{finding.score}</p>
                      </div>
                    )}
                  </div>
                  {finding.description && (
                    <div className="mt-6">
                      <h4 className="text-sm font-medium text-slate-300">Description</h4>
                      <p className="mt-2 text-sm leading-6 text-slate-400">{finding.description}</p>
                    </div>
                  )}
                  {finding.evidence && (
                    <div className="mt-6">
                      <h4 className="text-sm font-medium text-slate-300">Evidence</h4>
                      <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950 p-4">
                        <p className="break-words font-mono text-xs leading-6 text-slate-400">{finding.evidence}</p>
                      </div>
                    </div>
                  )}
                  {finding.remediation && (
                    <div className="mt-6">
                      <h4 className="text-sm font-medium text-slate-300">Remediation</h4>
                      <p className="mt-2 text-sm leading-6 text-slate-400">{finding.remediation}</p>
                    </div>
                  )}
                  {(finding.cve || finding.cwe) && (
                    <div className="mt-6 flex flex-wrap gap-3">
                      {finding.cve && <span className="rounded-md border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">CVE: {finding.cve}</span>}
                      {finding.cwe && <span className="rounded-md border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">CWE: {finding.cwe}</span>}
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
