"use client";

/* eslint-disable react-hooks/set-state-in-effect -- detail fetch on param change */
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import PageHeader from "@/components/ui/PageHeader";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import SeverityBadge from "@/components/ui/SeverityBadge";
import StatusBadge from "@/components/ui/StatusBadge";
import { getAsset, updateAsset } from "@/lib/api/assets";

function formatWhen(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function formatAssetType(value) {
  if (!value) return "—";
  return String(value).replaceAll("_", " ");
}

export default function AssetDetailPage() {
  const params = useParams();
  const assetId = params?.assetId;
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [crit, setCrit] = useState("");
  const [owner, setOwner] = useState("");
  const [adminMsg, setAdminMsg] = useState("");
  const [adminError, setAdminError] = useState("");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    if (!assetId) return;
    setLoading(true);
    setError("");
    try {
      const data = await getAsset(assetId);
      setDetail(data);
    } catch (err) {
      setError(err.message || "Unable to load security data.");
    } finally {
      setLoading(false);
    }
  }, [assetId]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <div>
        <PageHeader title="Asset detail" description="Loading asset security context..." />
        <div className="h-32 animate-pulse rounded-md bg-surface" />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="Asset detail" />
        <ErrorState title="Unable to load security data." message={error} onRetry={load} />
      </div>
    );
  }

  if (!detail) {
    return (
      <div>
        <PageHeader title="Asset detail" />
        <EmptyState title="Asset not found" description="The requested asset does not exist or you do not have access to its project." />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title={`${formatAssetType(detail.asset_type)}: ${detail.value}`}
        description={`Status: ${detail.status} • First seen ${formatWhen(detail.first_seen_at)} • Last seen ${formatWhen(detail.last_seen_at)}`}
        breadcrumb={<Link href="/assets" className="hover:underline">Assets</Link>}
        actions={
          <Link href="/assets" className="rounded-sm border border-border px-3 py-1.5 text-sm">
            Back to assets
          </Link>
        }
      />

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-md border border-border bg-surface p-4">
          <h3 className="text-sm font-semibold">Identity</h3>
          <dl className="mt-3 space-y-2 text-sm">
            <div className="flex justify-between"><dt className="text-muted">Type</dt><dd className="font-medium">{detail.asset_type}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Value</dt><dd className="font-medium break-all">{detail.value}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Status</dt><dd><StatusBadge status={detail.status} /></dd></div>
            <div className="flex justify-between"><dt className="text-muted">First seen</dt><dd>{formatWhen(detail.first_seen_at)}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Last seen</dt><dd>{formatWhen(detail.last_seen_at)}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">ID</dt><dd className="break-all text-xs">{detail.id}</dd></div>
          </dl>
          {detail.metadata && Object.keys(detail.metadata).length > 0 && (
            <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-canvas p-3 text-xs">{JSON.stringify(detail.metadata, null, 2)}</pre>
          )}
          <div className="mt-4 border-t border-border pt-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">Administration</h4>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Criticality</span>
                <select value={crit || detail.criticality || "unknown"} onChange={(e) => setCrit(e.target.value)} className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm" aria-label="Asset criticality">
                  {["critical", "high", "medium", "low", "unknown"].map((c) => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Owner (user UUID)</span>
                <input value={owner || detail.owner_user_id || ""} onChange={(e) => setOwner(e.target.value)} placeholder="Clear to unassign" className="rounded-sm border border-border bg-canvas px-2 py-1.5 font-mono text-sm" aria-label="Asset owner" />
              </label>
            </div>
            {adminError ? <p className="mt-2 text-xs text-red-400" role="alert">{adminError}</p> : null}
            {adminMsg ? <p className="mt-2 text-xs text-emerald-400" role="status">{adminMsg}</p> : null}
            <button
              type="button"
              disabled={saving}
              onClick={async () => {
                setAdminError("");
                setAdminMsg("");
                setSaving(true);
                try {
                  const payload = {};
                  if (crit && crit !== (detail.criticality || "unknown")) payload.criticality = crit;
                  const own = owner.trim();
                  if (own !== (detail.owner_user_id || "")) payload.owner_user_id = own || null;
                  if (Object.keys(payload).length === 0) {
                    setAdminError("No changes to save.");
                    return;
                  }
                  const updated = await updateAsset(assetId, payload);
                  setDetail((d) => ({ ...d, ...updated }));
                  setCrit("");
                  setOwner("");
                  setAdminMsg("Asset updated.");
                } catch (err) {
                  setAdminError(err.message || "Unable to update asset.");
                } finally {
                  setSaving(false);
                }
              }}
              className="mt-2 rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground disabled:opacity-60"
            >
              {saving ? "Saving..." : "Save criticality / owner"}
            </button>
          </div>
        </div>

        <div className="rounded-md border border-border bg-surface p-4">
          <h3 className="text-sm font-semibold">Security context</h3>
          {detail.security_summary ? (
            <dl className="mt-3 grid grid-cols-3 gap-2 text-sm">
              <div><dt className="text-muted">Findings</dt><dd className="font-semibold">{detail.security_summary.total_findings ?? 0}</dd></div>
              <div><dt className="text-muted">Critical</dt><dd className="font-semibold text-critical">{detail.security_summary.critical ?? 0}</dd></div>
              <div><dt className="text-muted">High</dt><dd className="font-semibold text-high">{detail.security_summary.high ?? 0}</dd></div>
              <div><dt className="text-muted">Exposed</dt><dd>{detail.security_summary.externally_exposed ? "Yes" : "No"}</dd></div>
              <div><dt className="text-muted">Changed</dt><dd>{detail.security_summary.recently_changed ? "Yes" : "No"}</dd></div>
              <div><dt className="text-muted">Highest</dt><dd>{detail.security_summary.highest_severity || "—"}</dd></div>
            </dl>
          ) : (
            <p className="mt-2 text-sm text-muted">Not available</p>
          )}
          {detail.classifications && (
            <div className="mt-4">
              <p className="text-xs font-medium">Classifications</p>
              <ul className="mt-2 grid grid-cols-2 gap-2 text-xs">
                {Object.entries(detail.classifications).map(([k, v]) => (
                  <li key={k} className={`rounded border px-2 py-1 ${v ? "border-success/30 bg-success/10" : "border-border"}`}>
                    {k.replaceAll("_", " ")}: {v ? "Yes" : "No"}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {detail.contextual_risk && (
            <div className="mt-4 rounded bg-canvas p-3">
              <p className="text-xs font-medium">Contextual risk: {detail.contextual_risk.priority}</p>
              <p className="mt-1 text-xs text-muted">{detail.contextual_risk.explanation}</p>
            </div>
          )}
        </div>
      </div>

      <div className="rounded-md border border-border bg-surface p-4">
        <h3 className="text-sm font-semibold">Relationships</h3>
        {!detail.relationships || detail.relationships.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No relationships.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {detail.relationships.map((rel) => {
              const related = rel.asset;
              return (
                <li key={rel.relationship_id} className="rounded border border-border bg-canvas px-3 py-2 text-sm">
                  <span className="font-medium">{rel.direction === "outgoing" ? detail.value : related?.value}</span>
                  <span className="mx-2 text-muted">↓ {rel.relationship_type} ↓</span>
                  <span className="font-medium">{rel.direction === "outgoing" ? related?.value : detail.value}</span>
                  <span className="ml-2 text-xs text-muted">({related?.asset_type})</span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="rounded-md border border-border bg-surface p-4">
        <h3 className="text-sm font-semibold">Findings</h3>
        {!detail.findings || detail.findings.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No findings associated with this asset.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {detail.findings.map((f) => (
              <li key={f.id} className="rounded border border-border bg-canvas px-3 py-2">
                <div className="flex justify-between gap-2">
                  <Link href={`/findings/${f.id}`} className="text-sm font-medium hover:underline">{f.title}</Link>
                  <SeverityBadge severity={f.severity} />
                </div>
                <p className="mt-1 text-xs text-muted">{f.scanner} • {f.status} • Score {f.score ?? "—"}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
