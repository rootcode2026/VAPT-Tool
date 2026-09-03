"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { API_BASE_URL as API_URL, apiFetch } from "@/lib/api/client";
import { severityClassName, severityLabel } from "@/lib/severity";

const SEVERITIES = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export default function FindingsPage() {
  const [findings, setFindings] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [scanner, setScanner] = useState("all");

  // ---------------------------------------------------------
  // Load findings
  // ---------------------------------------------------------

  async function loadFindings() {
    try {
      setLoading(true);
      setError("");

      const response = await apiFetch(
        `${API_URL}/api/v1/findings`,
        {
          cache: "no-store",
        }
      );

      if (!response.ok) {
        throw new Error(
          "Failed to load findings"
        );
      }

      const data = await response.json();

      setFindings(data);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to load findings"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const id = window.setTimeout(() => {
      loadFindings();
    }, 0);
    return () => window.clearTimeout(id);
  }, []);

  // ---------------------------------------------------------
  // Scanner list
  // ---------------------------------------------------------

  const scanners = useMemo(() => {
    const uniqueScanners = [
      ...new Set(
        findings
          .map((finding) => finding.scanner)
          .filter(Boolean)
      ),
    ];

    return uniqueScanners.sort();
  }, [findings]);

  // ---------------------------------------------------------
  // Filter findings
  // ---------------------------------------------------------

  const filteredFindings = useMemo(() => {
    const searchValue =
      search.trim().toLowerCase();

    return findings.filter((finding) => {
      // Severity
      if (
        severity !== "all" &&
        finding.severity?.toLowerCase() !==
          severity
      ) {
        return false;
      }

      // Scanner
      if (
        scanner !== "all" &&
        finding.scanner?.toLowerCase() !==
          scanner.toLowerCase()
      ) {
        return false;
      }

      // Search
      if (searchValue) {
        const searchableText = [
          finding.title,
          finding.description,
          finding.scanner,
          finding.cve,
          finding.cwe,
          finding.target_id,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();

        if (
          !searchableText.includes(
            searchValue
          )
        ) {
          return false;
        }
      }

      return true;
    });
  }, [
    findings,
    search,
    severity,
    scanner,
  ]);

  // ---------------------------------------------------------
  // Statistics
  // ---------------------------------------------------------

  const total = findings.length;

  const critical = findings.filter(
    (finding) =>
      finding.severity?.toLowerCase() ===
      "critical"
  ).length;

  const high = findings.filter(
    (finding) =>
      finding.severity?.toLowerCase() ===
      "high"
  ).length;

  const medium = findings.filter(
    (finding) =>
      finding.severity?.toLowerCase() ===
      "medium"
  ).length;

  const low = findings.filter(
    (finding) =>
      finding.severity?.toLowerCase() ===
      "low"
  ).length;

  const info = findings.filter(
    (finding) =>
      finding.severity?.toLowerCase() ===
      "info"
  ).length;

  // ---------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------

  function getSeverityClasses(value) {
    return `border ${severityClassName(value)}`;
  }

  function getStatusClasses(value) {
    switch (
      value?.toLowerCase()
    ) {
      case "open":
        return "text-red-400";

      case "resolved":
        return "text-emerald-400";

      case "false_positive":
        return "text-slate-400";

      case "accepted":
        return "text-yellow-400";

      default:
        return "text-slate-400";
    }
  }

  function formatSeverity(value) {
    return severityLabel(value);
  }

  function formatStatus(value) {
    if (!value) {
      return "Unknown";
    }

    return value
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) =>
        letter.toUpperCase()
      );
  }

  // ---------------------------------------------------------
  // Loading
  // ---------------------------------------------------------

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-blue-500" />

          <h1 className="text-xl font-semibold">
            Loading findings...
          </h1>

          <p className="mt-2 text-sm text-slate-500">
            Fetching security findings
          </p>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------
  // Main UI
  // ---------------------------------------------------------

  return (
    <div>
      {/* Header */}
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-3">
                <Link
                  href="/dashboard"
                  className="text-slate-500 transition hover:text-white"
                >
                  ←
                </Link>

                <h1 className="text-2xl font-bold">
                  Findings
                </h1>
              </div>

              <p className="mt-2 text-sm text-slate-400">
                Security vulnerabilities discovered by your scans.
              </p>
            </div>

            <button
              type="button"
              onClick={loadFindings}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-500 hover:bg-slate-900 hover:text-white"
            >
              Refresh
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Error */}
        {error && (
          <div className="mb-6 flex items-start justify-between gap-4 rounded-xl border border-red-900 bg-red-950/40 px-4 py-3">
            <div>
              <p className="font-medium text-red-400">
                Unable to load findings
              </p>

              <p className="mt-1 text-sm text-red-300">
                {error}
              </p>
            </div>

            <button
              type="button"
              onClick={() => setError("")}
              className="text-red-400 hover:text-red-300"
            >
              ×
            </button>
          </div>
        )}

        {/* Severity cards */}
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
          <SeverityCard
            label="Total"
            value={total}
            onClick={() =>
              setSeverity("all")
            }
            active={severity === "all"}
          />

          <SeverityCard
            label="Critical"
            value={critical}
            valueClass="text-red-400"
            onClick={() =>
              setSeverity("critical")
            }
            active={severity === "critical"}
          />

          <SeverityCard
            label="High"
            value={high}
            valueClass="text-orange-400"
            onClick={() =>
              setSeverity("high")
            }
            active={severity === "high"}
          />

          <SeverityCard
            label="Medium"
            value={medium}
            valueClass="text-yellow-400"
            onClick={() =>
              setSeverity("medium")
            }
            active={severity === "medium"}
          />

          <SeverityCard
            label="Low"
            value={low}
            valueClass="text-blue-400"
            onClick={() =>
              setSeverity("low")
            }
            active={severity === "low"}
          />

          <SeverityCard
            label="Info"
            value={info}
            valueClass="text-slate-400"
            onClick={() =>
              setSeverity("info")
            }
            active={severity === "info"}
          />
        </section>

        {/* Filters */}
        <section className="mt-8 rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="grid gap-4 lg:grid-cols-[1fr_200px_200px_auto]">
            {/* Search */}
            <div>
              <label
                htmlFor="finding-search"
                className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500"
              >
                Search
              </label>

              <input
                id="finding-search"
                type="text"
                value={search}
                onChange={(event) =>
                  setSearch(
                    event.target.value
                  )
                }
                placeholder="Search title, CVE, CWE, scanner..."
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-blue-500"
              />
            </div>

            {/* Severity */}
            <div>
              <label
                htmlFor="severity-filter"
                className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500"
              >
                Severity
              </label>

              <select
                id="severity-filter"
                value={severity}
                onChange={(event) =>
                  setSeverity(
                    event.target.value
                  )
                }
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-blue-500"
              >
                {SEVERITIES.map(
                  (item) => (
                    <option
                      key={item}
                      value={item}
                    >
                      {formatSeverity(item)}
                    </option>
                  )
                )}
              </select>
            </div>

            {/* Scanner */}
            <div>
              <label
                htmlFor="scanner-filter"
                className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500"
              >
                Scanner
              </label>

              <select
                id="scanner-filter"
                value={scanner}
                onChange={(event) =>
                  setScanner(
                    event.target.value
                  )
                }
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-blue-500"
              >
                <option value="all">
                  All scanners
                </option>

                {scanners.map(
                  (item) => (
                    <option
                      key={item}
                      value={item}
                    >
                      {item}
                    </option>
                  )
                )}
              </select>
            </div>

            {/* Clear */}
            <div className="flex items-end">
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setSeverity("all");
                  setScanner("all");
                }}
                className="w-full rounded-xl border border-slate-700 px-4 py-3 text-sm text-slate-300 transition hover:border-slate-500 hover:bg-slate-800 hover:text-white lg:w-auto"
              >
                Clear
              </button>
            </div>
          </div>

          <div className="mt-4 text-xs text-slate-500">
            Showing{" "}
            <span className="font-medium text-slate-300">
              {filteredFindings.length}
            </span>{" "}
            of{" "}
            <span className="font-medium text-slate-300">
              {findings.length}
            </span>{" "}
            findings
          </div>
        </section>

        {/* Findings */}
        <section className="mt-8">
          {filteredFindings.length ===
          0 ? (
            <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 px-6 py-16 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-slate-900 text-2xl">
                ✓
              </div>

              <h2 className="mt-4 text-lg font-semibold">
                No findings found
              </h2>

              <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
                No findings match your current search and filter settings.
              </p>

              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setSeverity("all");
                  setScanner("all");
                }}
                className="mt-5 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white"
              >
                Clear Filters
              </button>
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/50">
              {/* Desktop table */}
              <div className="hidden overflow-x-auto lg:block">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900">
                      <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                        Finding
                      </th>

                      <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                        Severity
                      </th>

                      <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                        Scanner
                      </th>

                      <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                        Score
                      </th>

                      <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                        Reference
                      </th>

                      <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                        Status
                      </th>

                      <th className="px-5 py-4 text-right text-xs font-medium uppercase tracking-wider text-slate-500">
                        Action
                      </th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800">
                    {filteredFindings.map(
                      (finding) => (
                        <tr
                          key={finding.id}
                          className="transition hover:bg-slate-900"
                        >
                          {/* Finding */}
                          <td className="max-w-md px-5 py-5">
                            <div className="font-medium text-white">
                              {finding.title}
                            </div>

                            {finding.description && (
                              <div className="mt-1 line-clamp-2 text-xs text-slate-500">
                                {
                                  finding.description
                                }
                              </div>
                            )}

                            <div className="mt-2 text-xs text-slate-600">
                              ID:{" "}
                              {finding.id}
                            </div>
                          </td>

                          {/* Severity */}
                          <td className="px-5 py-5">
                            <span
                              className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${getSeverityClasses(
                                finding.severity
                              )}`}
                            >
                              {formatSeverity(
                                finding.severity
                              )}
                            </span>
                          </td>

                          {/* Scanner */}
                          <td className="px-5 py-5">
                            <span className="rounded-lg bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-300">
                              {
                                finding.scanner
                              }
                            </span>
                          </td>

                          {/* Score */}
                          <td className="px-5 py-5">
                            {finding.score !==
                              null &&
                            finding.score !==
                              undefined ? (
                              <span className="font-semibold text-slate-200">
                                {
                                  finding.score
                                }
                              </span>
                            ) : (
                              <span className="text-slate-600">
                                —
                              </span>
                            )}
                          </td>

                          {/* Reference */}
                          <td className="px-5 py-5">
                            <div className="space-y-1 text-xs">
                              {finding.cve && (
                                <div className="text-slate-300">
                                  <span className="text-slate-600">
                                    CVE:
                                  </span>{" "}
                                  {
                                    finding.cve
                                  }
                                </div>
                              )}

                              {finding.cwe && (
                                <div className="text-slate-400">
                                  <span className="text-slate-600">
                                    CWE:
                                  </span>{" "}
                                  {
                                    finding.cwe
                                  }
                                </div>
                              )}

                              {!finding.cve &&
                                !finding.cwe && (
                                  <span className="text-slate-600">
                                    —
                                  </span>
                                )}
                            </div>
                          </td>

                          {/* Status */}
                          <td className="px-5 py-5">
                            <span
                              className={`text-sm font-medium ${getStatusClasses(
                                finding.status
                              )}`}
                            >
                              {formatStatus(
                                finding.status
                              )}
                            </span>
                          </td>

                          {/* Action */}
                          <td className="px-5 py-5 text-right">
                            <Link
                              href={`/findings/${finding.id}`}
                              className="inline-flex rounded-lg border border-slate-700 px-3 py-2 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:bg-slate-800 hover:text-white"
                            >
                              View
                            </Link>
                          </td>
                        </tr>
                      )
                    )}
                  </tbody>
                </table>
              </div>

              {/* Mobile cards */}
              <div className="divide-y divide-slate-800 lg:hidden">
                {filteredFindings.map(
                  (finding) => (
                    <div
                      key={finding.id}
                      className="p-5"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <h3 className="font-medium text-white">
                            {finding.title}
                          </h3>

                          <p className="mt-1 text-xs text-slate-600">
                            {
                              finding.scanner
                            }
                          </p>
                        </div>

                        <span
                          className={`shrink-0 rounded-full px-3 py-1 text-xs font-medium ${getSeverityClasses(
                            finding.severity
                          )}`}
                        >
                          {formatSeverity(
                            finding.severity
                          )}
                        </span>
                      </div>

                      <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
                        <div>
                          <p className="text-xs text-slate-500">
                            Scanner
                          </p>

                          <p className="mt-1 text-sm text-slate-200">
                            {
                              finding.scanner
                            }
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-500">
                            Score
                          </p>

                          <p className="mt-1 text-sm text-slate-200">
                            {finding.score ??
                              "—"}
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-500">
                            Status
                          </p>

                          <p
                            className={`mt-1 text-sm font-medium ${getStatusClasses(
                              finding.status
                            )}`}
                          >
                            {formatStatus(
                              finding.status
                            )}
                          </p>
                        </div>

                        <div className="flex items-end">
                          <Link
                            href={`/findings/${finding.id}`}
                            className="w-full rounded-lg border border-slate-700 px-3 py-2 text-center text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:bg-slate-800 hover:text-white"
                          >
                            View Details
                          </Link>
                        </div>
                      </div>

                      {(finding.cve ||
                        finding.cwe) && (
                        <div className="mt-4 rounded-lg bg-slate-950 p-3 text-xs">
                          {finding.cve && (
                            <div className="text-slate-300">
                              CVE:{" "}
                              {finding.cve}
                            </div>
                          )}

                          {finding.cwe && (
                            <div className="mt-1 text-slate-400">
                              CWE:{" "}
                              {finding.cwe}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                )}
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}


// ---------------------------------------------------------
// Severity Card
// ---------------------------------------------------------

function SeverityCard({
  label,
  value,
  valueClass = "text-white",
  onClick,
  active,
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-2xl border p-5 text-left transition ${
        active
          ? "border-blue-700 bg-blue-950/30"
          : "border-slate-800 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-900"
      }`}
    >
      <p className="text-sm text-slate-500">
        {label}
      </p>

      <p
        className={`mt-2 text-3xl font-bold ${valueClass}`}
      >
        {value}
      </p>
    </button>
  );
}