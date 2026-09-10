/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with bounded inbox */
/* D9 notifications — alert inbox + minimal policy settings. No chat, no composer. */
"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import PageHeader from "@/components/ui/PageHeader";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { SkeletonTable } from "@/components/ui/Skeleton";
import {
  getNotificationPolicy,
  listNotificationDeliveries,
  listNotifications,
  markNotificationRead,
  updateNotificationPolicy,
} from "@/lib/api/notifications";

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export default function ProjectNotificationsPage() {
  const params = useParams();
  const projectId = params?.project_id;
  const [items, setItems] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [policy, setPolicy] = useState(null);
  const [deliveries, setDeliveries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionOk, setActionOk] = useState("");

  const load = useCallback(async () => {
    if (!projectId) return;
    setLoading(true);
    setError("");
    try {
      const [inbox, pol, delivs] = await Promise.all([
        listNotifications(projectId, { limit: 100, ...(unreadOnly ? { unread: "true" } : {}) }),
        getNotificationPolicy(projectId).catch(() => null),
        listNotificationDeliveries(projectId, { limit: 50 }).catch(() => ({ items: [] })),
      ]);
      setItems(inbox.items || []);
      setUnreadCount(inbox.unread_count || 0);
      setPolicy(pol);
      setDeliveries(delivs.items || []);
    } catch (err) {
      setItems([]);
      setError(err.message || "Unable to load notifications.");
    } finally {
      setLoading(false);
    }
  }, [projectId, unreadOnly]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleMarkRead(id) {
    setActionError("");
    try {
      await markNotificationRead(projectId, id);
      await load();
    } catch (err) {
      setActionError(err.message || "Unable to mark as read.");
    }
  }

  async function handlePolicyChange(patch) {
    setActionError("");
    setActionOk("");
    try {
      const updated = await updateNotificationPolicy(projectId, { ...(policy || {}), ...patch });
      setPolicy(updated);
      setActionOk("Notification policy updated.");
    } catch (err) {
      setActionError(err.message || "Unable to update policy.");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notifications"
        description="Alert inbox and delivery policy. D3 alerts are authoritative; D9 only delivers them."
      />

      {actionError ? (
        <p className="text-sm text-red-400" role="alert">
          {actionError}
        </p>
      ) : null}
      {actionOk ? (
        <p className="text-sm text-emerald-400" role="status">
          {actionOk}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input type="checkbox" checked={unreadOnly} onChange={(e) => setUnreadOnly(e.target.checked)} />
          Unread only ({unreadCount})
        </label>
        <button
          type="button"
          onClick={load}
          className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
        >
          Retry
        </button>
      </div>

      {loading ? (
        <SkeletonTable rows={6} />
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : items.length === 0 ? (
        <EmptyState title="No notifications" message="No notifications for this project yet." />
      ) : (
        <div className="overflow-x-auto rounded-2xl border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 text-xs text-slate-500">
              <tr>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Received</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((n) => (
                <tr key={n.id} className="border-t border-slate-800">
                  <td className="px-4 py-3">
                    {n.alert_id ? (
                      <Link href="/alerts" className="text-blue-400 hover:underline">
                        {n.title}
                      </Link>
                    ) : (
                      n.title
                    )}
                    {n.summary ? <p className="mt-1 text-xs text-slate-500">{n.summary.slice(0, 160)}</p> : null}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={n.severity} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{n.notification_type}</td>
                  <td className="px-4 py-3 text-xs">{formatWhen(n.created_at)}</td>
                  <td className="px-4 py-3 text-xs">{n.read ? "Read" : "Unread"}</td>
                  <td className="px-4 py-3">
                    {!n.read ? (
                      <button
                        type="button"
                        onClick={() => handleMarkRead(n.id)}
                        className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                      >
                        Mark read
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Notification policy">
        <h2 className="text-lg font-semibold text-white">Delivery policy</h2>
        {!policy ? (
          <p className="mt-3 text-sm text-slate-500">Loading policy...</p>
        ) : (
          <div className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
            <label className="flex items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={!!policy.enabled}
                onChange={(e) => handlePolicyChange({ enabled: e.target.checked })}
              />
              Enabled
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-400">
              Channel
              <select
                value={policy.channel || "in_app"}
                onChange={(e) => handlePolicyChange({ channel: e.target.value })}
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
              >
                <option value="in_app">In-app</option>
                <option value="local">Local (testing)</option>
              </select>
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-400">
              Minimum severity
              <select
                value={policy.min_severity || "high"}
                onChange={(e) => handlePolicyChange({ min_severity: e.target.value })}
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-400">
              Recipients
              <select
                value={policy.recipient_mode || "finding_owner"}
                onChange={(e) => handlePolicyChange({ recipient_mode: e.target.value })}
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
              >
                <option value="finding_owner">Finding owner</option>
                <option value="project_analysts">Security analysts</option>
              </select>
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={!!policy.notify_on_redetection}
                onChange={(e) => handlePolicyChange({ notify_on_redetection: e.target.checked })}
              />
              Notify on redetection
            </label>
          </div>
        )}
        <p className="mt-3 text-xs text-slate-500">
          Policy changes require project admin and are audited. Delivery requires no external provider for In-app; Local
          delivers to a bounded test sink.
        </p>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Delivery history">
        <h2 className="text-lg font-semibold text-white">Delivery history</h2>
        {deliveries.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No deliveries yet.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {deliveries.map((d) => (
              <li key={d.id} className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
                <p className="text-sm font-medium">
                  {d.notification_type} • {d.channel} • {d.status}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Alert {d.alert_id ? d.alert_id.slice(0, 8) : "—"} • attempts {d.attempt_count}
                  {d.last_error ? ` • ${d.last_error.slice(0, 120)}` : ""}
                  {d.sent_at ? ` • sent ${formatWhen(d.sent_at)}` : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
