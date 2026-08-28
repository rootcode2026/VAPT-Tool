"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

const API_URL = "http://localhost:8000";

export default function FindingDetailsPage() {
  const params = useParams();

  const findingId = params?.finding_id;

  const [finding, setFinding] = useState(null);
  const [scan, setScan] = useState(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // ---------------------------------------------------------
  // Load finding
  // ---------------------------------------------------------

  async function loadFinding() {
    if (!findingId) {
      return;
    }

    try {
      setLoading(true);
      setError("");

      const findingResponse = await fetch(
        `${API_URL}/api/v1/findings/${findingId}`,
        {
          cache: "no-store",
        }
      );

      if (!findingResponse.ok) {
        if (findingResponse.status === 404) {
          throw new Error("Finding not found");
        }

        throw new Error(
          "Failed to load finding"
        );
      }

      const findingData =
        await findingResponse.json();

      setFinding(findingData);

      // -----------------------------------------------------
      // Load scan information
      // -----------------------------------------------------

      if (findingData.scan_id) {
        try {
          const scanResponse =
            await fetch(
              `${API_URL}/api/v1/scans/${findingData.scan_id}`,
              {
                cache: "no-store",
              }
            );

          if (scanResponse.ok) {
            const scanData =
              await scanResponse.json();

            setScan(scanData);
          }
        } catch (scanError) {
          console.error(
            "Failed to load scan information:",
            scanError
          );
        }
      }
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to load finding"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFinding();
  }, [findingId]);

  // ---------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------

  function getSeverityClasses(severity) {
    switch (
      severity?.toLowerCase()
    ) {
      case "critical":
        return "border-red-700 bg-red-950/70 text-red-400";

      case "high":
        return "border-orange-700 bg-orange-950/70 text-orange-400";

      case "medium":
        return "border-yellow-700 bg-yellow-950/70 text-yellow-400";

      case "low":
        return "border-blue-700 bg-blue-950/70 text-blue-400";

      case "info":
        return "border-slate-700 bg-slate-800 text-slate-400";

      default:
        return "border-slate-700 bg-slate-800 text-slate-400";
    }
  }

  function getStatusClasses(status) {
    switch (
      status?.toLowerCase()
    ) {
      case "open":
        return "border-red-800 bg-red-950/50 text-red-400";

      case "resolved":
        return "border-emerald-800 bg-emerald-950/50 text-emerald-400";

      case "accepted":
        return "border-yellow-800 bg-yellow-950/50 text-yellow-400";

      case "false_positive":
        return "border-slate-700 bg-slate-800 text-slate-400";

      default:
        return "border-slate-700 bg-slate-800 text-slate-400";
    }
  }

  function formatValue(value) {
    if (!value) {
      return "—";
    }

    return value;
  }

  function formatStatus(status) {
    if (!status) {
      return "Unknown";
    }

    return status
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) =>
        letter.toUpperCase()
      );
  }

  function formatSeverity(severity) {
    if (!severity) {
      return "Unknown";
    }

    return (
      severity.charAt(0).toUpperCase() +
      severity.slice(1)
    );
  }

  // ---------------------------------------------------------
  // Loading
  // ---------------------------------------------------------

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-blue-500" />

          <h1 className="text-xl font-semibold">
            Loading finding...
          </h1>

          <p className="mt-2 text-sm text-slate-500">
            Fetching vulnerability details
          </p>
        </div>
      </main>
    );
  }

  // ---------------------------------------------------------
  // Error
  // ---------------------------------------------------------

  if (error || !finding) {
    return (
      <main className="min-h-screen bg-slate-950 text-white">
        <div className="mx-auto max-w-4xl px-6 py-16">
          <Link
            href="/findings"
            className="text-sm text-slate-400 hover:text-white"
          >
            ← Back to Findings
          </Link>

          <div className="mt-8 rounded-2xl border border-red-900 bg-red-950/30 p-8">
            <h1 className="text-xl font-semibold text-red-400">
              Unable to load finding
            </h1>

            <p className="mt-2 text-sm text-red-300">
              {error ||
                "The requested finding could not be found."}
            </p>

            <Link
              href="/findings"
              className="mt-6 inline-flex rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white"
            >
              Return to Findings
            </Link>
          </div>
        </div>
      </main>
    );
  }

  // ---------------------------------------------------------
  // Main UI
  // ---------------------------------------------------------

  return (
    <main className="min-h-screen bg-slate-950 text-white">
      {/* Header */}
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <Link
                href="/findings"
                className="text-sm text-slate-500 transition hover:text-white"
              >
                ← Back to Findings
              </Link>

              <h1 className="mt-3 text-2xl font-bold">
                Finding Details
              </h1>

              <p className="mt-1 text-sm text-slate-400">
                Detailed security finding and remediation information.
              </p>
            </div>

            <Link
              href="/scans"
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-500 hover:bg-slate-900 hover:text-white"
            >
              Scan History
            </Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Finding title */}
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-3">
                <span
                  className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium ${getSeverityClasses(
                    finding.severity
                  )}`}
                >
                  {formatSeverity(
                    finding.severity
                  )}
                </span>

                <span
                  className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium ${getStatusClasses(
                    finding.status
                  )}`}
                >
                  {formatStatus(
                    finding.status
                  )}
                </span>
              </div>

              <h2 className="mt-4 text-2xl font-bold text-white">
                {finding.title}
              </h2>

              <p className="mt-3 break-all text-xs text-slate-600">
                Finding ID: {finding.id}
              </p>
            </div>

            {finding.score !==
              null &&
              finding.score !==
                undefined && (
                <div className="shrink-0 rounded-2xl border border-slate-700 bg-slate-950 px-6 py-4 text-center">
                  <p className="text-xs uppercase tracking-wider text-slate-500">
                    Score
                  </p>

                  <p className="mt-1 text-3xl font-bold text-white">
                    {finding.score}
                  </p>
                </div>
              )}
          </div>
        </section>

        {/* Metadata */}
        <section className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <InfoCard
            label="Scanner"
            value={formatValue(
              finding.scanner
            )}
          />

          <InfoCard
            label="Target ID"
            value={formatValue(
              finding.target_id
            )}
            mono
          />

          <InfoCard
            label="CVE"
            value={formatValue(
              finding.cve
            )}
            mono
          />

          <InfoCard
            label="CWE"
            value={formatValue(
              finding.cwe
            )}
            mono
          />
        </section>

        {/* Scan context */}
        {scan && (
          <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="mb-5">
              <h2 className="text-lg font-semibold">
                Scan Context
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Information about the scan that generated this finding.
              </p>
            </div>

            <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
              <InfoCard
                label="Scan ID"
                value={scan.id}
                mono
              />

              <InfoCard
                label="Profile"
                value={scan.profile}
              />

              <InfoCard
                label="Scan Status"
                value={formatStatus(
                  scan.status
                )}
              />

              <InfoCard
                label="Risk"
                value={
                  scan.risk_score !==
                  null &&
                  scan.risk_score !==
                    undefined
                    ? `${scan.risk_score} ${
                        scan.risk_grade
                          ? `(${scan.risk_grade})`
                          : ""
                      }`
                    : "Not calculated"
                }
              />
            </div>
          </section>
        )}

        {/* Description */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading
            title="Description"
            subtitle="What the scanner detected."
          />

          <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950 p-5">
            {finding.description ? (
              <p className="whitespace-pre-wrap text-sm leading-7 text-slate-300">
                {finding.description}
              </p>
            ) : (
              <p className="text-sm text-slate-600">
                No description was provided.
              </p>
            )}
          </div>
        </section>

        {/* Evidence */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading
            title="Evidence"
            subtitle="Technical evidence associated with this finding."
          />

          <div className="mt-5 overflow-hidden rounded-xl border border-slate-800 bg-slate-950">
            {finding.evidence ? (
              <pre className="max-h-[500px] overflow-auto whitespace-pre-wrap break-words p-5 font-mono text-xs leading-6 text-slate-300">
                {finding.evidence}
              </pre>
            ) : (
              <div className="p-5 text-sm text-slate-600">
                No evidence was provided.
              </div>
            )}
          </div>
        </section>

        {/* Remediation */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading
            title="Remediation"
            subtitle="Recommended steps to address this finding."
          />

          <div className="mt-5 rounded-xl border border-emerald-900/50 bg-emerald-950/20 p-5">
            {finding.remediation ? (
              <p className="whitespace-pre-wrap text-sm leading-7 text-slate-300">
                {finding.remediation}
              </p>
            ) : (
              <p className="text-sm text-slate-600">
                No remediation guidance was provided.
              </p>
            )}
          </div>
        </section>

        {/* Technical references */}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <SectionHeading
            title="Technical References"
            subtitle="Security classification references associated with this finding."
          />

          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            <ReferenceCard
              label="CVE"
              value={finding.cve}
              description="Common Vulnerabilities and Exposures"
            />

            <ReferenceCard
              label="CWE"
              value={finding.cwe}
              description="Common Weakness Enumeration"
            />
          </div>
        </section>

        {/* Bottom navigation */}
        <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-between">
          <Link
            href="/findings"
            className="rounded-lg border border-slate-700 px-5 py-3 text-center text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:bg-slate-900 hover:text-white"
          >
            ← Back to Findings
          </Link>

          {finding.scan_id && (
            <Link
              href={`/scans/${finding.scan_id}`}
              className="rounded-lg bg-blue-600 px-5 py-3 text-center text-sm font-semibold text-white transition hover:bg-blue-500"
            >
              View Scan Details →
            </Link>
          )}
        </div>
      </div>
    </main>
  );
}


// ---------------------------------------------------------
// Info Card
// ---------------------------------------------------------

function InfoCard({
  label,
  value,
  mono = false,
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <p className="text-xs uppercase tracking-wider text-slate-500">
        {label}
      </p>

      <p
        className={`mt-2 break-all text-sm font-medium text-slate-200 ${
          mono ? "font-mono text-xs" : ""
        }`}
      >
        {value || "—"}
      </p>
    </div>
  );
}


// ---------------------------------------------------------
// Section Heading
// ---------------------------------------------------------

function SectionHeading({
  title,
  subtitle,
}) {
  return (
    <div>
      <h2 className="text-lg font-semibold text-white">
        {title}
      </h2>

      {subtitle && (
        <p className="mt-1 text-sm text-slate-500">
          {subtitle}
        </p>
      )}
    </div>
  );
}


// ---------------------------------------------------------
// Reference Card
// ---------------------------------------------------------

function ReferenceCard({
  label,
  value,
  description,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-semibold text-slate-200">
            {label}
          </p>

          <p className="mt-1 text-xs text-slate-600">
            {description}
          </p>
        </div>

        <span className="font-mono text-sm text-slate-300">
          {value || "—"}
        </span>
      </div>
    </div>
  );
}