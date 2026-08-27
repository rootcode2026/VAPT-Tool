"use client";

import { useEffect, useState } from "react";
import AppShell from "@/components/layout/AppShell";

const API_URL = "http://localhost:8000";

export default function Home() {
  const [summary, setSummary] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDashboard() {
      try {
        setLoading(true);
        setError("");

        const [summaryResponse, scansResponse] =
          await Promise.all([
            fetch(
              `${API_URL}/api/v1/dashboard/summary`
            ),
            fetch(
              `${API_URL}/api/v1/scans`
            ),
          ]);

        if (!summaryResponse.ok) {
          throw new Error(
            "Failed to load dashboard summary"
          );
        }

        if (!scansResponse.ok) {
          throw new Error(
            "Failed to load scans"
          );
        }

        const summaryData =
          await summaryResponse.json();

        const scansData =
          await scansResponse.json();

        setSummary(summaryData);
        setScans(scansData);
      } catch (err) {
        console.error(err);

        setError(
          err.message ||
          "Failed to load dashboard"
        );
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  /*
   * -------------------------------------------------------
   * Loading
   * -------------------------------------------------------
   */

  if (loading) {
    return (
      <AppShell>
        <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
          <div className="text-center">
            <div className="text-xl font-semibold">
              Loading dashboard...
            </div>

            <p className="mt-2 text-slate-400">
              Fetching security data
            </p>
          </div>
        </main>
      </AppShell>
    );
  }

  /*
   * -------------------------------------------------------
   * Error
   * -------------------------------------------------------
   */

  if (error) {
    return (
      <AppShell>
        <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center p-6">
          <div className="max-w-md rounded-xl border border-red-900 bg-red-950/40 p-6">
            <h1 className="text-xl font-semibold text-red-400">
              Dashboard Error
            </h1>

            <p className="mt-2 text-slate-300">
              {error}
            </p>

            <p className="mt-4 text-sm text-slate-400">
              Make sure the backend is running on
              port 8000.
            </p>
          </div>
        </main>
      </AppShell>
    );
  }

  /*
   * -------------------------------------------------------
   * Dashboard
   * -------------------------------------------------------
   */

  return (
    <AppShell>
      <main className="min-h-screen bg-slate-950 text-white">

        {/* Header */}
        <header className="border-b border-slate-800">
          <div className="mx-auto max-w-7xl px-6 py-5">

            <div className="flex items-center justify-between">

              <div>
                <h1 className="text-2xl font-bold">
                  Security Dashboard
                </h1>

                <p className="mt-1 text-sm text-slate-400">
                  Security assessment overview
                </p>
              </div>

              <div className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm">
                System Status

                <span className="ml-2 text-green-400">
                  ● Healthy
                </span>
              </div>

            </div>

          </div>
        </header>

        {/* Content */}
        <div className="mx-auto max-w-7xl px-6 py-8">

          {/* -------------------------------------------------
              Scan Statistics
          -------------------------------------------------- */}

          <section>
            <h2 className="mb-4 text-lg font-semibold">
              Scan Overview
            </h2>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">

              <StatCard
                title="Total Scans"
                value={summary?.scans?.total ?? 0}
              />

              <StatCard
                title="Running"
                value={summary?.scans?.running ?? 0}
              />

              <StatCard
                title="Completed"
                value={summary?.scans?.completed ?? 0}
              />

              <StatCard
                title="Failed"
                value={summary?.scans?.failed ?? 0}
              />

            </div>
          </section>

          {/* -------------------------------------------------
              Risk Overview
          -------------------------------------------------- */}

          <section className="mt-8">

            <h2 className="mb-4 text-lg font-semibold">
              Risk Overview
            </h2>

            <div className="grid gap-4 lg:grid-cols-2">

              <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

                <p className="text-sm text-slate-400">
                  Average Risk Score
                </p>

                <div className="mt-3 text-5xl font-bold">
                  {summary?.risk?.average_score ?? "—"}
                </div>

                <p className="mt-2 text-sm text-slate-400">
                  Based on completed scan assessments
                </p>

              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

                <p className="text-sm text-slate-400">
                  Total Findings
                </p>

                <div className="mt-3 text-5xl font-bold">
                  {summary?.findings?.total ?? 0}
                </div>

                <p className="mt-2 text-sm text-slate-400">
                  Security findings detected
                </p>

              </div>

            </div>

          </section>

          {/* -------------------------------------------------
              Findings By Severity
          -------------------------------------------------- */}

          <section className="mt-8">

            <h2 className="mb-4 text-lg font-semibold">
              Findings by Severity
            </h2>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">

              <SeverityCard
                title="Critical"
                value={
                  summary?.findings?.critical ?? 0
                }
              />

              <SeverityCard
                title="High"
                value={
                  summary?.findings?.high ?? 0
                }
              />

              <SeverityCard
                title="Medium"
                value={
                  summary?.findings?.medium ?? 0
                }
              />

              <SeverityCard
                title="Low"
                value={
                  summary?.findings?.low ?? 0
                }
              />

              <SeverityCard
                title="Info"
                value={
                  summary?.findings?.info ?? 0
                }
              />

            </div>

          </section>

          {/* -------------------------------------------------
              Recent Scans
          -------------------------------------------------- */}

          <section className="mt-8">

            <div className="mb-4 flex items-center justify-between">

              <h2 className="text-lg font-semibold">
                Recent Scans
              </h2>

              <span className="text-sm text-slate-400">
                {scans.length} scans
              </span>

            </div>

            <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">

              {scans.length === 0 ? (

                <div className="p-6 text-center text-slate-400">
                  No scans found.
                </div>

              ) : (

                <div className="overflow-x-auto">

                  <table className="w-full text-left text-sm">

                    <thead className="border-b border-slate-800 bg-slate-950">

                      <tr>

                        <th className="px-6 py-4">
                          Scan ID
                        </th>

                        <th className="px-6 py-4">
                          Target
                        </th>

                        <th className="px-6 py-4">
                          Profile
                        </th>

                        <th className="px-6 py-4">
                          Status
                        </th>

                        <th className="px-6 py-4">
                          Risk
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {scans.map((scan) => (

                        <tr
                          key={scan.id}
                          className="border-b border-slate-800 last:border-0"
                        >

                          <td className="px-6 py-4 font-mono text-xs text-slate-400">
                            {scan.id}
                          </td>

                          <td className="px-6 py-4">
                            {scan.target_id}
                          </td>

                          <td className="px-6 py-4">
                            {scan.profile}
                          </td>

                          <td className="px-6 py-4">

                            <StatusBadge
                              status={scan.status}
                            />

                          </td>

                          <td className="px-6 py-4">
                            {scan.risk_score ?? "—"}
                          </td>

                        </tr>

                      ))}

                    </tbody>

                  </table>

                </div>

              )}

            </div>

          </section>

        </div>

      </main>
    </AppShell>
  );
}


/*
 * ---------------------------------------------------------
 * Stat Card
 * ---------------------------------------------------------
 */

function StatCard({ title, value }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

      <p className="text-sm text-slate-400">
        {title}
      </p>

      <p className="mt-3 text-3xl font-bold">
        {value}
      </p>

    </div>
  );
}


/*
 * ---------------------------------------------------------
 * Severity Card
 * ---------------------------------------------------------
 */

function SeverityCard({ title, value }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

      <p className="text-sm text-slate-400">
        {title}
      </p>

      <p className="mt-3 text-2xl font-bold">
        {value}
      </p>

    </div>
  );
}


/*
 * ---------------------------------------------------------
 * Status Badge
 * ---------------------------------------------------------
 */

function StatusBadge({ status }) {
  const normalized = status?.toLowerCase();

  let classes =
    "bg-slate-800 text-slate-300";

  if (normalized === "completed") {
    classes =
      "bg-green-950 text-green-400";
  }

  if (normalized === "running") {
    classes =
      "bg-blue-950 text-blue-400";
  }

  if (normalized === "queued") {
    classes =
      "bg-yellow-950 text-yellow-400";
  }

  if (normalized === "failed") {
    classes =
      "bg-red-950 text-red-400";
  }

  return (
    <span
      className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${classes}`}
    >
      {status}
    </span>
  );
}