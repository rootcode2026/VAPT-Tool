"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import { listFrameworks } from "@/lib/api/reports";

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const res = await listFrameworks();
        if (!cancelled) setFrameworks(res.items || []);
      } catch (e) {
        if (!cancelled) setError(e.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  if (loading) return <div><PageHeader title="Compliance" description="OWASP ASVS, Top 10, CIS, ISO 27001, NIST CSF, PCI DSS — evidence mappings, not certification" /><LoadingState message="Loading frameworks..." /></div>;
  if (error) return <div><PageHeader title="Compliance" /><ErrorState title="Unable to load" message={error} onRetry={() => window.location.reload()} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Compliance Intelligence" description="Extensible control mappings — technical evidence, not certification. Statuses: not_assessed, supported, partially_supported, needs_review." />
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {frameworks.map((fw) => (
          <Link key={fw.id} href={`/compliance/${fw.id}`} className="rounded-md border bg-surface p-4 hover:bg-surface-hover">
            <p className="text-sm font-semibold">{fw.display_name}</p>
            <p className="text-xs text-muted">{fw.framework} • v{fw.version}</p>
            <p className="mt-1 text-xs text-muted line-clamp-2">{fw.description}</p>
          </Link>
        ))}
      </div>
      <p className="text-xs text-muted">Each control traceable to findings/assets/scans/checks. Use “needs_review” where evidence insufficient; never auto-label compliant.</p>
    </div>
  );
}
