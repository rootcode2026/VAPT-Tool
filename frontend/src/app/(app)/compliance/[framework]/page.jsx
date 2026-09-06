"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import { listControls } from "@/lib/api/reports";

export default function ComplianceDetailPage() {
  const { framework } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const res = await listControls(framework);
        setData(res);
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [framework]);
  if (loading) return <div><PageHeader title="Compliance" /><LoadingState message="Loading controls..." /></div>;
  if (error) return <div><PageHeader title="Compliance" /><ErrorState title="Unable to load" message={error} onRetry={() => window.location.reload()} /></div>;
  return (
    <div className="space-y-6">
      <PageHeader title={data.display_name || framework} description={`Framework ${data.framework} • Coverage ${data.coverage?.coverage_percent || 0}%`} />
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Coverage</h3>
        <p className="text-xs text-muted">Supported: {data.coverage?.supported ?? 0} / {data.coverage?.total ?? 0} • {data.coverage?.coverage_percent ?? 0}%</p>
        <p className="text-xs text-muted">Not assessed: {data.coverage?.not_assessed ?? 0} • Needs review: {data.coverage?.needs_review ?? 0}</p>
      </div>
      <div className="rounded-md border bg-surface">
        <div className="border-b px-4 py-3"><h3 className="text-sm font-semibold">Controls</h3><p className="text-xs text-muted">Traceable to findings/assets/scans/checks. Status: not_assessed, supported, etc. — not certification.</p></div>
        <div className="divide-y">
          {(data.controls || []).map((c) => (
            <div key={c.id} className="p-3">
              <p className="text-sm font-medium">{c.control_id}: {c.title} <span className="rounded border px-1 text-xs">{c.status}</span></p>
              <p className="text-xs text-muted">{c.category} • {c.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
