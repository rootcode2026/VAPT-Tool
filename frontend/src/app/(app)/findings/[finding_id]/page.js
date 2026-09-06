"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { API_BASE_URL as API_URL, apiFetch } from "@/lib/api/client";
import { severityClassName, severityLabel } from "@/lib/severity";
import FindingWorkflow from "@/components/findings/FindingWorkflow";

function getMeta(finding) {
  return (finding?.metadata && typeof finding.metadata === "object" ? finding.metadata : {}) || {};
}
function getValidation(finding) {
  const meta = getMeta(finding);
  const state = finding?.validation_state || finding?.state || meta.validation_state || meta.state || meta.validationState || null;
  const score = finding?.confidence_score ?? meta.confidence_score ?? meta.confidenceScore ?? null;
  const level = finding?.confidence_level ?? meta.confidence_level ?? meta.confidenceLevel ?? null;
  const requires = meta.requires_human_review ?? finding?.requires_human_review ?? null;
  return { state, score, level, requires };
}
function getRisk(finding) {
  const meta = getMeta(finding);
  return {
    score: finding?.risk_score ?? meta.risk_score ?? finding?.score ?? null,
    level: finding?.risk_level ?? meta.risk_level ?? null,
    grade: finding?.risk_grade ?? meta.risk_grade ?? null,
    signals: meta.risk_signals || meta.signals || null,
    reasons: meta.risk_reasons || meta.reasons || null,
  };
}
function getProvenance(finding) {
  const meta = getMeta(finding);
  return {
    scanners: meta.scanners || (finding?.scanner ? [finding.scanner] : []),
    evidenceType: meta.evidence_type || meta.evidenceType || null,
    fingerprint: meta.fingerprint || null,
    hostname: meta.hostname || null,
    url: meta.url || finding?.url || null,
    ip: meta.ip || null,
    port: meta.port || null,
    parameter: meta.parameter || null,
    file: meta.file || null,
    line: meta.line || null,
    ruleId: meta.rule_id || meta.ruleId || finding?.rule_id || null,
  };
}
function getAssetContext(finding) {
  const meta = getMeta(finding);
  return {
    assetId: finding?.asset_id || meta.asset_id || null,
    assetType: finding?.asset_type || meta.asset_type || null,
    assetValue: finding?.asset_value || meta.asset_value || null,
    exposure: meta.exposure ?? meta.is_externally_exposed ?? null,
    status: meta.asset_status || null,
  };
}

export default function FindingDetailsPage() {
  const params = useParams();
  const findingId = params?.finding_id;
  const [finding, setFinding] = useState(null);
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadFinding = useCallback(async () => {
    if (!findingId) return;
    try {
      setLoading(true);
      setError("");
      const findingResponse = await apiFetch(`${API_URL}/api/v1/findings/${findingId}`, { cache: "no-store" });
      if (!findingResponse.ok) {
        if (findingResponse.status === 404) throw new Error("Finding not found");
        throw new Error("Failed to load finding");
      }
      const findingData = await findingResponse.json();
      setFinding(findingData);
      if (findingData.scan_id) {
        try {
          const scanResponse = await apiFetch(`${API_URL}/api/v1/scans/${findingData.scan_id}`, { cache: "no-store" });
          if (scanResponse.ok) {
            const scanData = await scanResponse.json();
            setScan(scanData);
          }
        } catch (scanError) {
          console.error("Failed to load scan information:", scanError);
        }
      }
    } catch (err) {
      console.error(err);
      setError(err.message || "Failed to load finding");
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    const id = window.setTimeout(() => { loadFinding(); }, 0);
    return () => window.clearTimeout(id);
  }, [findingId, loadFinding]);

  function getSeverityClasses(severity) {
    return `border ${severityClassName(severity)}`;
  }
  function getStatusClasses(status) {
    switch (status?.toLowerCase()) {
      case "open": return "border-red-800 bg-red-950/50 text-red-400";
      case "resolved": return "border-emerald-800 bg-emerald-950/50 text-emerald-400";
      case "accepted": return "border-yellow-800 bg-yellow-950/50 text-yellow-400";
      case "false_positive": return "border-slate-700 bg-slate-800 text-slate-400";
      default: return "border-slate-700 bg-slate-800 text-slate-400";
    }
  }
  function formatValue(value) { if (!value) return "—"; return value; }
  function formatStatus(status) {
    if (!status) return "Unknown";
    return status.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  }
  function formatSeverity(severity) { return severityLabel(severity); }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-blue-500" />
          <h1 className="text-xl font-semibold">Loading finding...</h1>
          <p className="mt-2 text-sm text-slate-500">Fetching vulnerability details</p>
        </div>
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div>
        <div className="mx-auto max-w-4xl px-6 py-16">
          <Link href="/findings" className="text-sm text-slate-400 hover:text-white">← Back to Findings</Link>
          <div className="mt-8 rounded-2xl border border-red-900 bg-red-950/30 p-8">
            <h1 className="text-xl font-semibold text-red-400">Unable to load finding</h1>
            <p className="mt-2 text-sm text-red-300">{error || "The requested finding could not be found."}</p>
            <Link href="/findings" className="mt-6 inline-flex rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white">Return to Findings</Link>
          </div>
        </div>
      </div>
    );
  }

  const validation = getValidation(finding);
  const risk = getRisk(finding);
  const provenance = getProvenance(finding);
  const assetCtx = getAssetContext(finding);

  return (
    <div>
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <Link href="/findings" className="text-sm text-slate-500 transition hover:text-white">← Back to Findings</Link>
              <h1 className="mt-3 text-2xl font-bold">Finding Details</h1>
              <p className="mt-1 text-sm text-slate-400">Detailed security finding, validation, risk and remediation information.</p>
            </div>
            <Link href="/scans" className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-500 hover:bg-slate-900 hover:text-white">Scan History</Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-3">
                <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium ${getSeverityClasses(finding.severity)}`}>{formatSeverity(finding.severity)}</span>
                <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium ${getStatusClasses(finding.status)}`}>{formatStatus(finding.status)}</span>
                {validation.state && (
                  <span className="inline-flex rounded-full border border-slate-700 bg-slate-800 px-3 py-1 text-xs font-medium text-slate-300">
                    Validation: {String(validation.state).replaceAll("_", " ")}
                  </span>
                )}
              </div>
              <h2 className="mt-4 text-2xl font-bold text-white">{finding.title}</h2>
              <p className="mt-3 break-all text-xs text-slate-600">Finding ID: {finding.id}</p>
              {validation.requires === true && <p className="mt-2 text-xs font-medium text-warning">Requires human review — automated detection, not human validated.</p>}
              {validation.requires === false && <p className="mt-2 text-xs font-medium text-success">Human validated</p>}
            </div>
            {finding.score !== null && finding.score !== undefined && (
              <div className="shrink-0 rounded-2xl border border-slate-700 bg-slate-950 px-6 py-4 text-center">
                <p className="text-xs uppercase tracking-wider text-slate-500">Score</p>
                <p className="mt-1 text-3xl font-bold text-white">{finding.score}</p>
              </div>
            )}
          </div>
        </section>

        <section className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <InfoCard label="Scanner" value={formatValue(finding.scanner)} />
          <InfoCard label="Target ID" value={formatValue(finding.target_id)} mono />
          <InfoCard label="CVE" value={formatValue(finding.cve)} mono />
          <InfoCard label="CWE" value={formatValue(finding.cwe)} mono />
        </section>

        {/* Validation */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Validation" subtitle="Corroboration and confidence. The backend is authoritative; the UI never auto-confirms findings." />
          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <InfoCard label="Validation State" value={validation.state ? String(validation.state).replaceAll("_", " ") : "Not available"} />
            <InfoCard label="Confidence Score" value={validation.score != null ? String(validation.score) : "Not available"} />
            <InfoCard label="Confidence Level" value={validation.level ? String(validation.level).replaceAll("_", " ") : "Not available"} />
          </div>
          <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
            <p className="text-sm font-medium text-slate-300">Human Review Safety</p>
            <p className="mt-1 text-xs text-slate-500">
              <span className="font-medium text-slate-300">Detected / Corroborated</span> — automated detection, requires human review. <span className="font-medium text-slate-300">Confirmed / False Positive / Accepted Risk</span> — human validated.
            </p>
            <p className="mt-2 text-xs text-muted">The UI must not label a scanner detection as “Verified” or “Confirmed”.</p>
            {validation.requires === true && <p className="mt-2 inline-flex rounded-full border border-warning/40 bg-warning/10 px-3 py-1 text-xs text-warning">Requires human review</p>}
          </div>
        </section>

        {/* Risk */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Risk" subtitle="Risk score, level, grade and contributing signals from backend risk intelligence. Displayed verbatim." />
          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <InfoCard label="Risk Score" value={risk.score != null ? String(risk.score) : "Not available"} />
            <InfoCard label="Risk Level" value={risk.level ? String(risk.level).replaceAll("_", " ") : "Not available"} />
            <InfoCard label="Grade" value={risk.grade ? String(risk.grade) : "Not available"} />
          </div>
          {risk.signals && (
            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs font-medium text-slate-300">Risk Signals</p>
              <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words text-xs text-slate-400">{JSON.stringify(risk.signals, null, 2)}</pre>
            </div>
          )}
          {risk.reasons && Array.isArray(risk.reasons) && risk.reasons.length > 0 && (
            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs font-medium text-slate-300">Risk Reasons</p>
              <ul className="mt-2 list-disc pl-4 text-xs text-slate-400">
                {risk.reasons.map((r, i) => (
                  <li key={i}>{String(r)}</li>
                ))}
              </ul>
            </div>
          )}
          {!risk.score && !risk.level && !risk.grade && <p className="mt-4 text-sm text-slate-600">No enriched risk available — showing score from finding if present.</p>}
        </section>

        {/* Asset context */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Affected Asset" subtitle="Asset association, exposure and navigational context." />
          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            <InfoCard label="Asset ID" value={assetCtx.assetId || finding.asset_id || "Not available"} mono />
            <InfoCard label="Asset Type" value={assetCtx.assetType || "Not available"} />
            <InfoCard label="Asset Value" value={assetCtx.assetValue || "Not available"} mono />
            <InfoCard label="Exposure" value={assetCtx.exposure != null ? String(assetCtx.exposure) : "Not available"} />
          </div>
          {assetCtx.assetId || finding.asset_id ? (
            <Link href={`/assets/${assetCtx.assetId || finding.asset_id}`} className="mt-4 inline-flex rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">View Asset →</Link>
          ) : (
            <p className="mt-4 text-sm text-slate-600">No asset association for this finding.</p>
          )}
          <Link href="/attack-surface" className="ml-3 inline-flex rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">View Attack Surface →</Link>
        </section>

        {/* Provenance */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Provenance" subtitle="Scanner provenance and evidence type. Bounded evidence from backend." />
          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <InfoCard label="Scanners" value={provenance.scanners?.length ? provenance.scanners.join(", ") : finding.scanner || "Not available"} />
            <InfoCard label="Evidence Type" value={provenance.evidenceType ? String(provenance.evidenceType).replaceAll("_", " ") : "Not available"} />
            <InfoCard label="Rule ID" value={provenance.ruleId || "Not available"} mono />
          </div>
          <div className="mt-4 grid gap-4 sm:grid-cols-2">
            <InfoCard label="Hostname" value={provenance.hostname || "Not available"} mono />
            <InfoCard label="URL" value={provenance.url || "Not available"} mono />
            <InfoCard label="IP" value={provenance.ip || "Not available"} mono />
            <InfoCard label="Port" value={provenance.port || "Not available"} />
            <InfoCard label="Parameter" value={provenance.parameter || "Not available"} />
            <InfoCard label="File:Line" value={provenance.file ? `${provenance.file}${provenance.line ? `:${provenance.line}` : ""}` : "Not available"} mono />
          </div>
        </section>

        {scan && (
          <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="mb-5">
              <h2 className="text-lg font-semibold">Scan Context</h2>
              <p className="mt-1 text-sm text-slate-500">Information about the scan that generated this finding.</p>
            </div>
            <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
              <InfoCard label="Scan ID" value={scan.id} mono />
              <InfoCard label="Profile" value={scan.profile} />
              <InfoCard label="Scan Status" value={formatStatus(scan.status)} />
              <InfoCard label="Risk" value={scan.risk_score !== null && scan.risk_score !== undefined ? `${scan.risk_score} ${scan.risk_grade ? `(${scan.risk_grade})` : ""}` : "Not calculated"} />
            </div>
          </section>
        )}

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Description" subtitle="What the scanner detected." />
          <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950 p-5">
            {finding.description ? <p className="whitespace-pre-wrap text-sm leading-7 text-slate-300">{finding.description}</p> : <p className="text-sm text-slate-600">No description was provided.</p>}
          </div>
        </section>

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Evidence" subtitle="Technical evidence associated with this finding. Evidence type indicates how it was observed." />
          <div className="mt-5 overflow-hidden rounded-xl border border-slate-800 bg-slate-950">
            {finding.evidence ? <pre className="max-h-[500px] overflow-auto whitespace-pre-wrap break-words p-5 font-mono text-xs leading-6 text-slate-300">{finding.evidence}</pre> : <div className="p-5 text-sm text-slate-600">No evidence was provided.</div>}
          </div>
          <p className="mt-2 text-xs text-slate-500">Controlled evidence types include: scanner_output, http_response, http_request, url, hostname, ip, port, source_code, dependency, etc.</p>
        </section>

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Remediation" subtitle="Recommended steps to address this finding." />
          <div className="mt-5 rounded-xl border border-emerald-900/50 bg-emerald-950/20 p-5">
            {finding.remediation ? <p className="whitespace-pre-wrap text-sm leading-7 text-slate-300">{finding.remediation}</p> : <p className="text-sm text-slate-600">No remediation guidance was provided.</p>}
          </div>
        </section>

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading title="Technical References" subtitle="Security classification references associated with this finding." />
          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            <ReferenceCard label="CVE" value={finding.cve} description="Common Vulnerabilities and Exposures" />
            <ReferenceCard label="CWE" value={finding.cwe} description="Common Weakness Enumeration" />
          </div>
        </section>

        <FindingWorkflow findingId={findingId} initial={finding} onChanged={(updated) => setFinding((prev) => ({ ...prev, ...updated }))} />

        <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-between">
          <Link href="/findings" className="rounded-lg border border-slate-700 px-5 py-3 text-center text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:bg-slate-900 hover:text-white">← Back to Findings</Link>
          {finding.scan_id && <Link href={`/scans/${finding.scan_id}`} className="rounded-lg bg-blue-600 px-5 py-3 text-center text-sm font-semibold text-white transition hover:bg-blue-500">View Scan Details →</Link>}
        </div>
      </div>
    </div>
  );
}

function InfoCard({ label, value, mono = false }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-2 break-all text-sm font-medium text-slate-200 ${mono ? "font-mono text-xs" : ""}`}>{value || "—"}</p>
    </div>
  );
}
function SectionHeading({ title, subtitle }) {
  return (
    <div>
      <h2 className="text-lg font-semibold text-white">{title}</h2>
      {subtitle && <p className="mt-1 text-sm text-slate-500">{subtitle}</p>}
    </div>
  );
}
function ReferenceCard({ label, value, description }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-semibold text-slate-200">{label}</p>
          <p className="mt-1 text-xs text-slate-600">{description}</p>
        </div>
        <span className="font-mono text-sm text-slate-300">{value || "—"}</span>
      </div>
    </div>
  );
}
