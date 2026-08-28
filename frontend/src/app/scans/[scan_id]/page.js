"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

const API_URL = "http://localhost:8000";

export default function ScanDetailsPage() {
  const params = useParams();
  const scanId = params?.scan_id;

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadScanDetails() {
    if (!scanId) {
      return;
    }

    try {
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/scans/${scanId}/details`,
        {
          cache: "no-store",
        }
      );

      if (!response.ok) {
        const errorData =
          await response.json().catch(() => null);

        throw new Error(
          errorData?.detail ||
            "Failed to load scan details"
        );
      }

      const result = await response.json();

      setData(result);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to load scan details"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadScanDetails();
  }, [scanId]);

  /*
   * ---------------------------------------------------------
   * Loading
   * ---------------------------------------------------------
   */

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-xl font-semibold">
            Loading scan...
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            Fetching scan details
          </p>
        </div>
      </main>
    );
  }

  /*
   * ---------------------------------------------------------
   * Error
   * ---------------------------------------------------------
   */

  if (error || !data) {
    return (
      <main className="min-h-screen bg-slate-950 text-white">
        <div className="mx-auto max-w-5xl px-6 py-10">

          <Link
            href="/scans"
            className="text-sm text-slate-400 hover:text-white"
          >
            ← Back to Scans
          </Link>

          <div className="mt-8 rounded-xl border border-red-900 bg-red-950/30 p-6">
            <h1 className="text-lg font-semibold text-red-300">
              Unable to load scan
            </h1>

            <p className="mt-2 text-sm text-red-400">
              {error || "Scan not found"}
            </p>
          </div>

        </div>
      </main>
    );
  }

  const scan = data.scan;
  const findings = data.findings || [];

  /*
   * ---------------------------------------------------------
   * Finding statistics
   * ---------------------------------------------------------
   */

  const counts = {
    critical: findings.filter(
      (finding) =>
        finding.severity?.toLowerCase() ===
        "critical"
    ).length,

    high: findings.filter(
      (finding) =>
        finding.severity?.toLowerCase() ===
        "high"
    ).length,

    medium: findings.filter(
      (finding) =>
        finding.severity?.toLowerCase() ===
        "medium"
    ).length,

    low: findings.filter(
      (finding) =>
        finding.severity?.toLowerCase() ===
        "low"
    ).length,

    info: findings.filter(
      (finding) =>
        finding.severity?.toLowerCase() ===
        "info"
    ).length,
  };

  /*
   * ---------------------------------------------------------
   * Helpers
   * ---------------------------------------------------------
   */

  function statusClasses(status) {
    switch (status?.toLowerCase()) {
      case "completed":
        return "bg-green-950 text-green-400";

      case "running":
        return "bg-blue-950 text-blue-400";

      case "queued":
        return "bg-yellow-950 text-yellow-400";

      case "failed":
        return "bg-red-950 text-red-400";

      default:
        return "bg-slate-800 text-slate-400";
    }
  }

  function severityClasses(severity) {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "bg-red-950 text-red-300";

      case "high":
        return "bg-orange-950 text-orange-300";

      case "medium":
        return "bg-yellow-950 text-yellow-300";

      case "low":
        return "bg-blue-950 text-blue-300";

      case "info":
        return "bg-slate-800 text-slate-300";

      default:
        return "bg-slate-800 text-slate-300";
    }
  }

  function scannerClasses(scanner) {
    if (scanner === "nmap") {
      return "bg-purple-950 text-purple-300";
    }

    if (scanner === "nuclei") {
      return "bg-cyan-950 text-cyan-300";
    }

    return "bg-slate-800 text-slate-300";
  }

  function formatProfile(profile) {
    if (!profile) {
      return "Unknown";
    }

    return (
      profile.charAt(0).toUpperCase() +
      profile.slice(1)
    );
  }

  /*
   * ---------------------------------------------------------
   * Main
   * ---------------------------------------------------------
   */

  return (
    <main className="min-h-screen bg-slate-950 text-white">

      {/* Header */}
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-6">

          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">

            <div>

              <Link
                href="/scans"
                className="text-sm text-slate-400 hover:text-white"
              >
                ← Back to Scans
              </Link>

              <h1 className="mt-3 text-2xl font-bold">
                Scan Details
              </h1>

              <p className="mt-1 text-sm text-slate-400">
                Security assessment results
              </p>

            </div>

            <span
              className={`inline-flex w-fit rounded-full px-3 py-1 text-xs font-medium capitalize ${statusClasses(
                scan.status
              )}`}
            >
              {scan.status}
            </span>

          </div>

        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">

        {/* ---------------------------------------------------
            Scan Information
        ---------------------------------------------------- */}

        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">

          <h2 className="text-lg font-semibold">
            Scan Information
          </h2>

          <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Scan ID
              </p>

              <p className="mt-2 break-all text-sm text-slate-300">
                {scan.id}
              </p>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Target ID
              </p>

              <p className="mt-2 break-all text-sm text-slate-300">
                {scan.target_id}
              </p>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Profile
              </p>

              <p className="mt-2 text-sm text-slate-300">
                {formatProfile(scan.profile)}
              </p>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Status
              </p>

              <p className="mt-2 capitalize text-sm text-slate-300">
                {scan.status}
              </p>
            </div>

          </div>

        </section>

        {/* ---------------------------------------------------
            Risk Assessment
        ---------------------------------------------------- */}

        <section className="mb-8">

          <h2 className="mb-4 text-lg font-semibold">
            Risk Assessment
          </h2>

          <div className="grid gap-4 sm:grid-cols-3">

            {/* Score */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

              <p className="text-sm text-slate-400">
                Risk Score
              </p>

              <p className="mt-2 text-4xl font-bold">
                {scan.risk_score ??
                  "—"}
              </p>

              <p className="mt-2 text-xs text-slate-500">
                Overall security score
              </p>

            </div>

            {/* Grade */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

              <p className="text-sm text-slate-400">
                Risk Grade
              </p>

              <p className="mt-2 text-4xl font-bold">
                {scan.risk_grade ??
                  "—"}
              </p>

              <p className="mt-2 text-xs text-slate-500">
                Assessment grade
              </p>

            </div>

            {/* Level */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

              <p className="text-sm text-slate-400">
                Risk Level
              </p>

              <p className="mt-2 text-2xl font-bold capitalize">
                {scan.risk_level ??
                  "—"}
              </p>

              <p className="mt-2 text-xs text-slate-500">
                Current risk classification
              </p>

            </div>

          </div>

        </section>

        {/* ---------------------------------------------------
            Finding Summary
        ---------------------------------------------------- */}

        <section className="mb-8">

          <div className="mb-4">

            <h2 className="text-lg font-semibold">
              Finding Summary
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              {findings.length} total finding
              {findings.length !== 1
                ? "s"
                : ""}
            </p>

          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">

            <SummaryCard
              label="Critical"
              value={counts.critical}
              className="text-red-400"
            />

            <SummaryCard
              label="High"
              value={counts.high}
              className="text-orange-400"
            />

            <SummaryCard
              label="Medium"
              value={counts.medium}
              className="text-yellow-400"
            />

            <SummaryCard
              label="Low"
              value={counts.low}
              className="text-blue-400"
            />

            <SummaryCard
              label="Info"
              value={counts.info}
              className="text-slate-300"
            />

          </div>

        </section>

        {/* ---------------------------------------------------
            Findings
        ---------------------------------------------------- */}

        <section>

          <div className="mb-4">

            <h2 className="text-lg font-semibold">
              Findings
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Security issues discovered during
              this scan.
            </p>

          </div>

          {findings.length === 0 ? (

            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-12 text-center">

              <h3 className="text-lg font-semibold">
                No findings
              </h3>

              <p className="mt-2 text-sm text-slate-400">
                No security findings were detected
                during this scan.
              </p>

            </div>

          ) : (

            <div className="space-y-4">

              {findings.map(
                (finding, index) => (

                  <article
                    key={
                      finding.id ||
                      `${finding.title}-${index}`
                    }
                    className="rounded-xl border border-slate-800 bg-slate-900 p-6"
                  >

                    {/* Finding header */}

                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">

                      <div className="min-w-0">

                        <div className="mb-3 flex flex-wrap items-center gap-2">

                          <span
                            className={`rounded-md px-2.5 py-1 text-xs font-medium uppercase ${scannerClasses(
                              finding.scanner
                            )}`}
                          >
                            {finding.scanner}
                          </span>

                          <span
                            className={`rounded-md px-2.5 py-1 text-xs font-medium uppercase ${severityClasses(
                              finding.severity
                            )}`}
                          >
                            {finding.severity}
                          </span>

                        </div>

                        <h3 className="text-lg font-semibold">
                          {finding.title}
                        </h3>

                      </div>

                      {finding.score !==
                        null &&
                        finding.score !==
                          undefined && (
                          <div className="shrink-0 text-right">

                            <p className="text-xs text-slate-500">
                              Score
                            </p>

                            <p className="text-xl font-bold">
                              {finding.score}
                            </p>

                          </div>
                        )}

                    </div>

                    {/* Description */}

                    {finding.description && (
                      <div className="mt-6">

                        <h4 className="text-sm font-medium text-slate-300">
                          Description
                        </h4>

                        <p className="mt-2 text-sm leading-6 text-slate-400">
                          {finding.description}
                        </p>

                      </div>
                    )}

                    {/* Evidence */}

                    {finding.evidence && (
                      <div className="mt-6">

                        <h4 className="text-sm font-medium text-slate-300">
                          Evidence
                        </h4>

                        <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950 p-4">

                          <p className="break-words font-mono text-xs leading-6 text-slate-400">
                            {finding.evidence}
                          </p>

                        </div>

                      </div>
                    )}

                    {/* Remediation */}

                    {finding.remediation && (
                      <div className="mt-6">

                        <h4 className="text-sm font-medium text-slate-300">
                          Remediation
                        </h4>

                        <p className="mt-2 text-sm leading-6 text-slate-400">
                          {finding.remediation}
                        </p>

                      </div>
                    )}

                    {/* CVE / CWE */}

                    {(finding.cve ||
                      finding.cwe) && (
                      <div className="mt-6 flex flex-wrap gap-3">

                        {finding.cve && (
                          <span className="rounded-md border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
                            CVE:{" "}
                            {finding.cve}
                          </span>
                        )}

                        {finding.cwe && (
                          <span className="rounded-md border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
                            CWE:{" "}
                            {finding.cwe}
                          </span>
                        )}

                      </div>
                    )}

                  </article>

                )
              )}

            </div>

          )}

        </section>

      </div>
    </main>
  );
}

/*
 * ---------------------------------------------------------
 * Summary Card
 * ---------------------------------------------------------
 */

function SummaryCard({
  label,
  value,
  className,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

      <p className="text-sm text-slate-400">
        {label}
      </p>

      <p
        className={`mt-2 text-3xl font-bold ${className}`}
      >
        {value}
      </p>

    </div>
  );
}