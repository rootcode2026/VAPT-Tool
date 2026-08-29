"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

const API_URL = "http://localhost:8000";

export default function ScansPage() {
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);

  const [loading, setLoading] = useState(true);
  const [targetsLoading, setTargetsLoading] = useState(true);

  const [error, setError] = useState("");
  const [targetsError, setTargetsError] = useState("");

  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedProfile, setSelectedProfile] =
    useState("quick");

  const [starting, setStarting] = useState(false);

  /*
   * ---------------------------------------------------------
   * Load targets
   * ---------------------------------------------------------
   */

  async function loadTargets() {
    try {
      setTargetsError("");

      const response = await fetch(
        `${API_URL}/api/v1/targets`,
        {
          cache: "no-store",
        }
      );

      if (!response.ok) {
        const errorData =
          await response.json().catch(() => null);

        throw new Error(
          errorData?.detail ||
            "Failed to load targets"
        );
      }

      const result = await response.json();

      setTargets(result);

      if (
        result.length > 0 &&
        !selectedTarget
      ) {
        setSelectedTarget(result[0].id);
      }
    } catch (err) {
      console.error(err);

      setTargetsError(
        err.message ||
          "Failed to load targets"
      );
    } finally {
      setTargetsLoading(false);
    }
  }

  /*
   * ---------------------------------------------------------
   * Load scans
   * ---------------------------------------------------------
   */

  async function loadScans() {
    try {
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/scans`,
        {
          cache: "no-store",
        }
      );

      if (!response.ok) {
        const errorData =
          await response.json().catch(() => null);

        throw new Error(
          errorData?.detail ||
            "Failed to load scans"
        );
      }

      const result = await response.json();

      setScans(result);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to load scans"
      );
    } finally {
      setLoading(false);
    }
  }

  /*
   * ---------------------------------------------------------
   * Initial load
   * ---------------------------------------------------------
   */

  useEffect(() => {
    loadTargets();
    loadScans();
  }, []);

  /*
   * ---------------------------------------------------------
   * Auto refresh active scans
   * ---------------------------------------------------------
   */

  useEffect(() => {
    const hasActiveScans = scans.some(
      (scan) =>
        scan.status === "queued" ||
        scan.status === "running"
    );

    if (!hasActiveScans) {
      return;
    }

    const interval = setInterval(() => {
      loadScans();
    }, 3000);

    return () => {
      clearInterval(interval);
    };
  }, [scans]);

  /*
   * ---------------------------------------------------------
   * Start scan
   * ---------------------------------------------------------
   */

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

      const response = await fetch(
        `${API_URL}/api/v1/scans`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            target_id: selectedTarget,
            profile: selectedProfile,
          }),
        }
      );

      if (!response.ok) {
        const errorData =
          await response.json().catch(() => null);

        throw new Error(
          errorData?.detail ||
            "Failed to start scan"
        );
      }

      await response.json();

      await loadScans();
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to start scan"
      );
    } finally {
      setStarting(false);
    }
  }

  /*
   * ---------------------------------------------------------
   * Target lookup
   * ---------------------------------------------------------
   */

  const targetMap = useMemo(() => {
    const map = {};

    for (const target of targets) {
      map[target.id] = target;
    }

    return map;
  }, [targets]);

  function getTargetValue(targetId) {
    return (
      targetMap[targetId]?.value ||
      targetId
    );
  }

  function getTargetType(targetId) {
    return (
      targetMap[targetId]?.type ||
      "unknown"
    );
  }

  /*
   * ---------------------------------------------------------
   * Phase helpers
   * ---------------------------------------------------------
   */

  function getPhaseLabel(phase) {
    if (!phase) {
      return "—";
    }

    return phase
      .split("_")
      .map(
        (word) =>
          word.charAt(0).toUpperCase() +
          word.slice(1)
      )
      .join(" ");
  }

  function getPhaseClasses(phase) {
    switch (phase) {
      case "queued":
        return "border border-yellow-800 bg-yellow-950/60 text-yellow-400";

      case "scanning":
        return "border border-blue-800 bg-blue-950/60 text-blue-400";

      case "nmap_completed":
        return "border border-purple-800 bg-purple-950/60 text-purple-400";

      case "nuclei_completed":
        return "border border-cyan-800 bg-cyan-950/60 text-cyan-400";

      case "analyzing":
        return "border border-indigo-800 bg-indigo-950/60 text-indigo-400";

      case "completed":
        return "border border-emerald-800 bg-emerald-950/60 text-emerald-400";

      case "failed":
        return "border border-red-800 bg-red-950/60 text-red-400";

      default:
        return "border border-slate-700 bg-slate-800 text-slate-400";
    }
  }

  /*
   * ---------------------------------------------------------
   * Status helpers
   * ---------------------------------------------------------
   */

  function getStatusLabel(status) {
    if (!status) {
      return "Unknown";
    }

    return (
      status.charAt(0).toUpperCase() +
      status.slice(1)
    );
  }

  function getStatusClasses(status) {
    switch (status?.toLowerCase()) {
      case "completed":
        return "bg-emerald-950 text-emerald-400";

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

  /*
   * ---------------------------------------------------------
   * Risk helpers
   * ---------------------------------------------------------
   */

  function getRiskClasses(grade) {
    switch (grade) {
      case "A":
        return "text-emerald-400";

      case "B":
        return "text-green-400";

      case "C":
        return "text-yellow-400";

      case "D":
        return "text-red-400";

      default:
        return "text-slate-500";
    }
  }

  /*
   * ---------------------------------------------------------
   * Profile label
   * ---------------------------------------------------------
   */

  function getProfileLabel(profile) {
    if (!profile) {
      return "Unknown";
    }

    return (
      profile.charAt(0).toUpperCase() +
      profile.slice(1) +
      " Scan"
    );
  }

  /*
   * ---------------------------------------------------------
   * Summary statistics
   * ---------------------------------------------------------
   */

  const summary = useMemo(() => {
    return {
      total: scans.length,

      completed: scans.filter(
        (scan) =>
          scan.status === "completed"
      ).length,

      running: scans.filter(
        (scan) =>
          scan.status === "running"
      ).length,

      queued: scans.filter(
        (scan) =>
          scan.status === "queued"
      ).length,

      failed: scans.filter(
        (scan) =>
          scan.status === "failed"
      ).length,
    };
  }, [scans]);

  /*
   * ---------------------------------------------------------
   * Loading
   * ---------------------------------------------------------
   */

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-white">

        <div className="mx-auto max-w-7xl px-6 py-10">

          <div className="flex min-h-[60vh] items-center justify-center">

            <div className="text-center">

              <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-white" />

              <p className="mt-4 text-sm text-slate-400">
                Loading scans...
              </p>

            </div>

          </div>

        </div>

      </main>
    );
  }

  /*
   * ---------------------------------------------------------
   * Main
   * ---------------------------------------------------------
   */

  return (
    <main className="min-h-screen bg-slate-950 text-white">

      {/* =====================================================
          HEADER
      ====================================================== */}

      <header className="border-b border-slate-800">

        <div className="mx-auto max-w-7xl px-6 py-8">

          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">

            <div>

              <h1 className="text-2xl font-bold">
                Scans
              </h1>

              <p className="mt-1 text-sm text-slate-400">
                Run and monitor security assessments
              </p>

            </div>

            <Link
              href="/dashboard"
              className="text-sm text-slate-400 hover:text-white"
            >
              ← Dashboard
            </Link>

          </div>

        </div>

      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">

        {/* ===================================================
            ERROR
        ==================================================== */}

        {(error || targetsError) && (
          <div className="mb-6 rounded-xl border border-red-900 bg-red-950/30 p-4">

            <p className="text-sm text-red-400">
              {error || targetsError}
            </p>

          </div>
        )}

        {/* ===================================================
            START SCAN
        ==================================================== */}

        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-6">

            <h2 className="text-lg font-semibold">
              Start New Scan
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Select a target and scan profile.
            </p>

          </div>

          <form
            onSubmit={startScan}
            className="grid gap-4 lg:grid-cols-[1fr_1fr_auto]"
          >

            {/* Target */}

            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Target
              </label>

              <select
                value={selectedTarget}
                onChange={(event) =>
                  setSelectedTarget(
                    event.target.value
                  )
                }
                disabled={targetsLoading}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
              >

                <option value="">
                  {targetsLoading
                    ? "Loading targets..."
                    : "Select target"}
                </option>

                {targets.map((target) => (
                  <option
                    key={target.id}
                    value={target.id}
                  >
                    {target.value}
                  </option>
                ))}

              </select>

            </div>

            {/* Profile */}

            <div>

              <label className="mb-2 block text-sm font-medium text-slate-300">
                Scan Profile
              </label>

              <select
                value={selectedProfile}
                onChange={(event) =>
                  setSelectedProfile(
                    event.target.value
                  )
                }
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
              >

                <option value="quick">
                  Quick Scan
                </option>

                <option value="web">
                  Web Scan
                </option>

                <option value="full">
                  Full Scan
                </option>

              </select>

            </div>

            {/* Button */}

            <div className="flex items-end">

              <button
                type="submit"
                disabled={
                  starting ||
                  !selectedTarget
                }
                className="w-full rounded-lg bg-white px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50 lg:w-auto"
              >
                {starting
                  ? "Starting..."
                  : "Start Scan"}
              </button>

            </div>

          </form>

        </section>

        {/* ===================================================
            SUMMARY
        ==================================================== */}

        <section className="mb-8">

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">

            <SummaryCard
              label="Total Scans"
              value={summary.total}
            />

            <SummaryCard
              label="Completed"
              value={summary.completed}
            />

            <SummaryCard
              label="Running"
              value={summary.running}
            />

            <SummaryCard
              label="Queued"
              value={summary.queued}
            />

            <SummaryCard
              label="Failed"
              value={summary.failed}
            />

          </div>

        </section>

        {/* ===================================================
            SCAN HISTORY
        ==================================================== */}

        <section>

          <div className="mb-5">

            <h2 className="text-lg font-semibold">
              Scan History
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Monitor previous and active security
              assessments.
            </p>

          </div>

          {scans.length === 0 ? (

            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-12 text-center">

              <h3 className="text-lg font-semibold">
                No scans yet
              </h3>

              <p className="mt-2 text-sm text-slate-400">
                Start your first security scan above.
              </p>

            </div>

          ) : (

            <>

              {/* =================================================
                  DESKTOP TABLE
              ================================================== */}

              <div className="hidden overflow-hidden rounded-xl border border-slate-800 bg-slate-900 lg:block">

                <div className="overflow-x-auto">

                  <table className="w-full">

                    <thead className="border-b border-slate-800 bg-slate-950/50">

                      <tr>

                        <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                          Target
                        </th>

                        <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                          Profile
                        </th>

                        <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                          Status
                        </th>

                        <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                          Phase
                        </th>

                        <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                          Risk
                        </th>

                        <th className="px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                          Findings
                        </th>

                        <th className="px-5 py-4 text-right text-xs font-medium uppercase tracking-wider text-slate-500">
                          Action
                        </th>

                      </tr>

                    </thead>

                    <tbody className="divide-y divide-slate-800">

                      {scans.map((scan) => {

                        const targetValue =
                          getTargetValue(
                            scan.target_id
                          );

                        return (
                          <tr
                            key={scan.id}
                            className="transition hover:bg-slate-800/40"
                          >

                            {/* Target */}

                            <td className="px-5 py-5">

                              <div>

                                <p className="font-medium text-white">
                                  {targetValue}
                                </p>

                                <p className="mt-1 text-xs text-slate-500">
                                  {getTargetType(
                                    scan.target_id
                                  )}
                                </p>

                              </div>

                            </td>

                            {/* Profile */}

                            <td className="px-5 py-5">

                              <span className="text-sm text-slate-300">
                                {getProfileLabel(
                                  scan.profile
                                )}
                              </span>

                            </td>

                            {/* Status */}

                            <td className="px-5 py-5">

                              <span
                                className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${getStatusClasses(
                                  scan.status
                                )}`}
                              >
                                {getStatusLabel(
                                  scan.status
                                )}
                              </span>

                            </td>

                            {/* Phase */}

                            <td className="px-5 py-5">

                              <span
                                className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${getPhaseClasses(
                                  scan.phase
                                )}`}
                              >

                                {(scan.status ===
                                  "queued" ||
                                  scan.status ===
                                    "running") && (
                                  <span className="mr-2 h-1.5 w-1.5 self-center animate-pulse rounded-full bg-current" />
                                )}

                                {getPhaseLabel(
                                  scan.phase
                                )}

                              </span>

                            </td>

                            {/* Risk */}

                            <td className="px-5 py-5">

                              {scan.risk_score !==
                              null &&
                              scan.risk_score !==
                                undefined ? (

                                <div>

                                  <p
                                    className={`text-lg font-bold ${getRiskClasses(
                                      scan.risk_grade
                                    )}`}
                                  >
                                    {scan.risk_score}
                                  </p>

                                  <p className="text-xs text-slate-500">
                                    Grade{" "}
                                    {scan.risk_grade ||
                                      "—"}
                                  </p>

                                </div>

                              ) : (

                                <span className="text-sm text-slate-600">
                                  —
                                </span>

                              )}

                            </td>

                            {/* Findings */}

                            <td className="px-5 py-5">

                              <span className="text-sm text-slate-300">
                                {scan.findings_count ??
                                  0}
                              </span>

                            </td>

                            {/* Action */}

                            <td className="px-5 py-5 text-right">

                              <Link
                                href={`/scans/${scan.id}`}
                                className="inline-flex rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"
                              >
                                View Details
                              </Link>

                            </td>

                          </tr>
                        );
                      })}

                    </tbody>

                  </table>

                </div>

              </div>

              {/* =================================================
                  MOBILE CARDS
              ================================================== */}

              <div className="space-y-4 lg:hidden">

                {scans.map((scan) => {

                  const targetValue =
                    getTargetValue(
                      scan.target_id
                    );

                  return (
                    <article
                      key={scan.id}
                      className="rounded-xl border border-slate-800 bg-slate-900 p-5"
                    >

                      {/* Header */}

                      <div className="flex items-start justify-between gap-4">

                        <div className="min-w-0">

                          <p className="break-all font-medium text-white">
                            {targetValue}
                          </p>

                          <p className="mt-1 text-xs text-slate-500">
                            {getTargetType(
                              scan.target_id
                            )}
                          </p>

                        </div>

                        <span
                          className={`shrink-0 rounded-full px-3 py-1 text-xs font-medium ${getStatusClasses(
                            scan.status
                          )}`}
                        >
                          {getStatusLabel(
                            scan.status
                          )}
                        </span>

                      </div>

                      {/* Details */}

                      <div className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-5">

                        <div>

                          <p className="text-xs text-slate-500">
                            Profile
                          </p>

                          <p className="mt-1 text-sm text-slate-300">
                            {getProfileLabel(
                              scan.profile
                            )}
                          </p>

                        </div>

                        <div>

                          <p className="text-xs text-slate-500">
                            Phase
                          </p>

                          <span
                            className={`mt-1 inline-flex rounded-full px-2 py-1 text-xs font-medium ${getPhaseClasses(
                              scan.phase
                            )}`}
                          >

                            {(scan.status ===
                              "queued" ||
                              scan.status ===
                                "running") && (
                              <span className="mr-1.5 h-1.5 w-1.5 self-center animate-pulse rounded-full bg-current" />
                            )}

                            {getPhaseLabel(
                              scan.phase
                            )}

                          </span>

                        </div>

                        <div>

                          <p className="text-xs text-slate-500">
                            Risk
                          </p>

                          {scan.risk_score !==
                            null &&
                          scan.risk_score !==
                            undefined ? (

                            <p
                              className={`mt-1 text-lg font-bold ${getRiskClasses(
                                scan.risk_grade
                              )}`}
                            >
                              {scan.risk_score}
                              <span className="ml-1 text-xs font-medium">
                                {scan.risk_grade}
                              </span>
                            </p>

                          ) : (

                            <p className="mt-1 text-sm text-slate-600">
                              —
                            </p>

                          )}

                        </div>

                        <div>

                          <p className="text-xs text-slate-500">
                            Findings
                          </p>

                          <p className="mt-1 text-sm text-slate-300">
                            {scan.findings_count ??
                              0}
                          </p>

                        </div>

                        <div className="flex items-end">

                          <Link
                            href={`/scans/${scan.id}`}
                            className="w-full rounded-lg border border-slate-700 px-3 py-2 text-center text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"
                          >
                            View Details
                          </Link>

                        </div>

                      </div>

                    </article>
                  );
                })}

              </div>

            </>

          )}

        </section>

      </div>

    </main>
  );
}

/*
 * =========================================================
 * Summary Card
 * =========================================================
 */

function SummaryCard({
  label,
  value,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

      <p className="text-sm text-slate-400">
        {label}
      </p>

      <p className="mt-2 text-3xl font-bold text-white">
        {value}
      </p>

    </div>
  );
}