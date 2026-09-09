"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import { downloadReport, getReport } from "@/lib/api/reports";

export default function ReportDetailPage() {
  const { report_id } = useParams();
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [dlMsg, setDlMsg] = useState("");
  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const r = await getReport(report_id);
        setReport(r);
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [report_id]);
  async function handleDownload(fmt) {
    setDlMsg("");
    try {
      await downloadReport(report_id, fmt);
    } catch (e) {
      setDlMsg(e.message);
    }
  }
  if (loading) return <div><PageHeader title="Report" /><LoadingState message="Loading report..." /></div>;
  if (error) return <div><PageHeader title="Report" /><ErrorState title="Unable to load" message={error} onRetry={() => window.location.reload()} /></div>;
  return (
    <div className="space-y-6">
      <PageHeader title={report.title} description={`${report.report_type} • ${report.status} • v${report.version}`} />
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Summary</h3>
        <pre className="mt-2 overflow-auto rounded bg-canvas p-3 text-xs">{JSON.stringify(report.summary, null, 2)}</pre>
      </div>
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Content</h3>
        <pre className="mt-2 overflow-auto rounded bg-canvas p-3 text-xs">{JSON.stringify(report.content, null, 2)}</pre>
      </div>
      <div className="flex gap-2">
        <button type="button" onClick={() => handleDownload("json")} className="rounded border px-3 py-1 text-xs">Download JSON</button>
        <button type="button" onClick={() => handleDownload("csv")} className="rounded border px-3 py-1 text-xs">Download CSV</button>
        <button type="button" onClick={() => handleDownload("pdf")} className="rounded border px-3 py-1 text-xs">Download PDF</button>
      </div>
      {dlMsg ? <p className="text-xs text-danger">{dlMsg}</p> : null}
      <p className="text-xs text-muted">CONFIDENTIAL — AUTHORIZED USE ONLY. Version {report.version}, data as of {report.data_as_of}.</p>
    </div>
  );
}
