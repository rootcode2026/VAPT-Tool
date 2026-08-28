"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

const API_URL = "http://localhost:8000";

const PROFILES = [
  {
    value: "quick",
    name: "Quick Scan",
    description: "Fast security assessment",
  },
  {
    value: "web",
    name: "Web Scan",
    description: "Web vulnerability assessment",
  },
  {
    value: "full",
    name: "Full Scan",
    description: "Comprehensive security assessment",
  },
];

export default function ScansPage() {
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);

  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedProfile, setSelectedProfile] = useState("quick");

  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  // ---------------------------------------------------------
  // Load targets
  // ---------------------------------------------------------

  async function loadTargets() {
    const response = await fetch(
      `${API_URL}/api/v1/targets`,
      {
        cache: "no-store",
      }
    );

    if (!response.ok) {
      throw new Error("Failed to load targets");
    }

    const data = await response.json();

    setTargets(data);

    if (!selectedTarget && data.length > 0) {
      setSelectedTarget(data[0].id);
    }
  }

  // ---------------------------------------------------------
  // Load scans
  // ---------------------------------------------------------

  async function loadScans() {
    const response = await fetch(
      `${API_URL}/api/v1/scans`,
      {
        cache: "no-store",
      }
    );

    if (!response.ok) {
      throw new Error("Failed to load scans");
    }

    const data = await response.json();

    setScans(data);
  }

  // ---------------------------------------------------------
  // Load page data
  // ---------------------------------------------------------

  async function loadData() {
    try {
      setLoading(true);
      setError("");

      await Promise.all([
        loadTargets(),
        loadScans(),
      ]);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to load scan information"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  // ---------------------------------------------------------
  // Auto refresh
  // ---------------------------------------------------------

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
      loadScans().catch((err) => {
        console.error(
          "Failed to refresh scans:",
          err
        );
      });
    }, 3000);

    return () => clearInterval(interval);
  }, [scans]);

  // ---------------------------------------------------------
  // Start scan
  // ---------------------------------------------------------

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
          await response.json().catch(
            () => null
          );

        throw new Error(
          errorData?.detail ||
            "Failed to start scan"
        );
      }

      const newScan = await response.json();

      /*
       * The create endpoint returns the basic
       * ScanResponse, so refresh the history
       * to get target + findings_count.
       */

      await loadScans();

      /*
       * Keep the newly created scan visible
       * even if the refresh races with the API.
       */

      setScans((current) => {
        const exists = current.some(
          (scan) => scan.id === newScan.id
        );

        if (exists) {
          return current;
        }

        return [
          {
            ...newScan,
            target:
              targets.find(
                (target) =>
                  target.id ===
                  newScan.target_id
              )?.value ||
              "Unknown target",
            findings_count: 0,
          },
          ...current,
        ];
      });
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

  // ---------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------

  function getStatusClasses(status) {
    switch (status) {
      case "completed":
        return "border border-emerald-800 bg-emerald-950/60 text-emerald-400";

      case "running":
        return "border border-blue-800 bg-blue-950/60 text-blue-400";

      case "queued":
        return "border border-yellow-800 bg-yellow-950/60 text-yellow-400";

      case "failed":
        return "border border-red-800 bg-red-950/60 text-red-400";

      default:
        return "border border-slate-700 bg-slate-800 text-slate-400";
    }
  }

  function getStatusLabel(status) {
    switch (status) {
      case "completed":
        return "Completed";

      case "running":
        return "Running";

      case "queued":
        return "Queued";

      case "failed":
        return "Failed";

      default:
        return status || "Unknown";
    }
  }

  function getProfileName(profile) {
    const item = PROFILES.find(
      (item) => item.value === profile
    );

    return item?.name || profile;
  }

  function getProfileDescription(profile) {
    const item = PROFILES.find(
      (item) => item.value === profile
    );

    return item?.description || "";
  }

  function getRiskClasses(score) {
    if (score === null || score === undefined) {
      return "border-slate-700 bg-slate-900 text-slate-400";
    }

    if (score >= 90) {
      return "border-emerald-800 bg-emerald-950/60 text-emerald-400";
    }

    if (score >= 75) {
      return "border-green-800 bg-green-950/60 text-green-400";
    }

    if (score >= 50) {
      return "border-yellow-800 bg-yellow-950/60 text-yellow-400";
    }

    if (score >= 25) {
      return "border-orange-800 bg-orange-950/60 text-orange-400";
    }

    return "border-red-800 bg-red-950/60 text-red-400";
  }

  function getTargetType(targetId) {
    const target = targets.find(
      (item) => item.id === targetId
    );

    return target?.target_type || "";
  }

  // ---------------------------------------------------------
  // Statistics
  // ---------------------------------------------------------

  const totalScans = scans.length;

  const runningScans = scans.filter(
    (scan) =>
      scan.status === "running"
  ).length;

  const queuedScans = scans.filter(
    (scan) =>
      scan.status === "queued"
  ).length;

  const completedScans = scans.filter(
    (scan) =>
      scan.status === "completed"
  ).length;

  const failedScans = scans.filter(
    (scan) =>
      scan.status === "failed"
  ).length;

  // ---------------------------------------------------------
  // Loading
  // ---------------------------------------------------------

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-blue-500" />

          <div className="text-xl font-semibold">
            Loading scans...
          </div>

          <p className="mt-2 text-sm text-slate-400">
            Fetching scan information
          </p>
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
              <div className="flex items-center gap-3">
                <Link
                  href="/dashboard"
                  className="text-slate-500 transition hover:text-white"
                >
                  ←
                </Link>

                <h1 className="text-2xl font-bold">
                  Security Scans
                </h1>
              </div>

              <p className="mt-2 text-sm text-slate-400">
                Run and monitor security assessments.
              </p>
            </div>

            <Link
              href="/dashboard"
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-500 hover:bg-slate-900 hover:text-white"
            >
              Dashboard
            </Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Error */}
        {error && (
          <div className="mb-6 flex items-start justify-between gap-4 rounded-xl border border-red-900 bg-red-950/40 px-4 py-3">
            <div>
              <p className="font-medium text-red-400">
                Something went wrong
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

        {/* Statistics */}
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <StatCard
            label="Total Scans"
            value={totalScans}
          />

          <StatCard
            label="Running"
            value={runningScans}
            valueClass="text-blue-400"
          />

          <StatCard
            label="Queued"
            value={queuedScans}
            valueClass="text-yellow-400"
          />

          <StatCard
            label="Completed"
            value={completedScans}
            valueClass="text-emerald-400"
          />

          <StatCard
            label="Failed"
            value={failedScans}
            valueClass="text-red-400"
          />
        </section>

        {/* Start Scan */}
        <section className="mt-8 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="mb-6">
            <h2 className="text-lg font-semibold">
              Start New Scan
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Select a target and scanning profile.
            </p>
          </div>

          {targets.length === 0 ? (
            <div className="rounded-xl border border-yellow-900 bg-yellow-950/30 p-5">
              <p className="font-medium text-yellow-400">
                No targets available
              </p>

              <p className="mt-1 text-sm text-yellow-300/80">
                Add a target before starting a scan.
              </p>

              <Link
                href="/targets"
                className="mt-4 inline-block rounded-lg bg-yellow-500 px-4 py-2 text-sm font-medium text-slate-950 transition hover:bg-yellow-400"
              >
                Manage Targets
              </Link>
            </div>
          ) : (
            <form
              onSubmit={startScan}
              className="grid gap-5 lg:grid-cols-3"
            >
              {/* Target */}
              <div>
                <label
                  htmlFor="target"
                  className="mb-2 block text-sm font-medium text-slate-300"
                >
                  Target
                </label>

                <select
                  id="target"
                  value={selectedTarget}
                  onChange={(event) =>
                    setSelectedTarget(
                      event.target.value
                    )
                  }
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                >
                  {targets.map((target) => (
                    <option
                      key={target.id}
                      value={target.id}
                    >
                      {target.value}
                    </option>
                  ))}
                </select>

                {selectedTarget && (
                  <p className="mt-2 text-xs text-slate-500">
                    Type:{" "}
                    {getTargetType(
                      selectedTarget
                    ) || "unknown"}
                  </p>
                )}
              </div>

              {/* Profile */}
              <div>
                <label
                  htmlFor="profile"
                  className="mb-2 block text-sm font-medium text-slate-300"
                >
                  Scan Profile
                </label>

                <select
                  id="profile"
                  value={selectedProfile}
                  onChange={(event) =>
                    setSelectedProfile(
                      event.target.value
                    )
                  }
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                >
                  {PROFILES.map((profile) => (
                    <option
                      key={profile.value}
                      value={profile.value}
                    >
                      {profile.name}
                    </option>
                  ))}
                </select>

                <p className="mt-2 text-xs text-slate-500">
                  {getProfileDescription(
                    selectedProfile
                  )}
                </p>
              </div>

              {/* Button */}
              <div className="flex items-end">
                <button
                  type="submit"
                  disabled={
                    starting ||
                    !selectedTarget
                  }
                  className="w-full rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {starting
                    ? "Starting Scan..."
                    : "Start Scan"}
                </button>
              </div>
            </form>
          )}
        </section>

        {/* Scan History */}
        <section className="mt-8">
          <div className="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold">
                Scan History
              </h2>

              <p className="mt-1 text-sm text-slate-400">
                View previous and active security assessments.
              </p>
            </div>

            {(runningScans > 0 ||
              queuedScans > 0) && (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <span className="h-2 w-2 animate-pulse rounded-full bg-blue-400" />
                Updating automatically
              </div>
            )}
          </div>

          {scans.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 px-6 py-16 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-slate-900 text-2xl">
                ⚡
              </div>

              <h3 className="mt-4 text-lg font-semibold">
                No scans yet
              </h3>

              <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
                Start your first security scan using
                the form above.
              </p>
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/50">
              {/* Desktop table */}
              <div className="hidden overflow-x-auto lg:block">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900">
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
                    {scans.map((scan) => (
                      <tr
                        key={scan.id}
                        className="transition hover:bg-slate-900"
                      >
                        {/* Target */}
                        <td className="px-5 py-5">
                          <div className="font-medium text-white">
                            {scan.target ||
                              "Unknown target"}
                          </div>

                          <div className="mt-1 max-w-xs truncate text-xs text-slate-500">
                            {scan.id}
                          </div>
                        </td>

                        {/* Profile */}
                        <td className="px-5 py-5">
                          <div className="text-sm text-slate-200">
                            {getProfileName(
                              scan.profile
                            )}
                          </div>

                          <div className="mt-1 text-xs text-slate-500">
                            {scan.profile}
                          </div>
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

                        {/* Risk */}
                        <td className="px-5 py-5">
                          {scan.risk_score !==
                            null &&
                          scan.risk_score !==
                            undefined ? (
                            <div className="flex items-center gap-2">
                              <span
                                className={`inline-flex min-w-9 items-center justify-center rounded-lg border px-2 py-1 text-xs font-semibold ${getRiskClasses(
                                  scan.risk_score
                                )}`}
                              >
                                {scan.risk_score}
                              </span>

                              <span className="text-sm font-medium text-slate-300">
                                {scan.risk_grade ||
                                  "—"}
                              </span>
                            </div>
                          ) : (
                            <span className="text-sm text-slate-600">
                              —
                            </span>
                          )}
                        </td>

                        {/* Findings */}
                        <td className="px-5 py-5">
                          <span className="text-sm font-medium text-slate-200">
                            {scan.findings_count ??
                              0}
                          </span>

                          <span className="ml-1 text-xs text-slate-500">
                            findings
                          </span>
                        </td>

                        {/* Action */}
                        <td className="px-5 py-5 text-right">
                          <Link
                            href={`/scans/${scan.id}`}
                            className="inline-flex rounded-lg border border-slate-700 px-3 py-2 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:bg-slate-800 hover:text-white"
                          >
                            View Details
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile / tablet cards */}
              <div className="divide-y divide-slate-800 lg:hidden">
                {scans.map((scan) => (
                  <div
                    key={scan.id}
                    className="p-5"
                  >
                    <div className="flex flex-col gap-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <h3 className="truncate font-medium text-white">
                            {scan.target ||
                              "Unknown target"}
                          </h3>

                          <p className="mt-1 truncate text-xs text-slate-500">
                            {scan.id}
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

                      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                        <div>
                          <p className="text-xs text-slate-500">
                            Profile
                          </p>

                          <p className="mt-1 text-sm text-slate-200">
                            {getProfileName(
                              scan.profile
                            )}
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-500">
                            Risk
                          </p>

                          <div className="mt-1 flex items-center gap-2">
                            <span className="text-sm font-semibold text-slate-200">
                              {scan.risk_score ??
                                "—"}
                            </span>

                            {scan.risk_grade && (
                              <span className="text-xs text-slate-500">
                                Grade{" "}
                                {
                                  scan.risk_grade
                                }
                              </span>
                            )}
                          </div>
                        </div>

                        <div>
                          <p className="text-xs text-slate-500">
                            Findings
                          </p>

                          <p className="mt-1 text-sm text-slate-200">
                            {scan.findings_count ??
                              0}
                          </p>
                        </div>

                        <div className="flex items-end">
                          <Link
                            href={`/scans/${scan.id}`}
                            className="w-full rounded-lg border border-slate-700 px-3 py-2 text-center text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:bg-slate-800 hover:text-white"
                          >
                            View Details
                          </Link>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}


// ---------------------------------------------------------
// Stat Card
// ---------------------------------------------------------

function StatCard({
  label,
  value,
  valueClass = "text-white",
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <p className="text-sm text-slate-500">
        {label}
      </p>

      <p
        className={`mt-2 text-3xl font-bold ${valueClass}`}
      >
        {value}
      </p>
    </div>
  );
}