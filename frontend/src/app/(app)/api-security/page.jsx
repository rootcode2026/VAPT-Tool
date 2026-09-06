/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { useProjectContext } from "@/lib/project-context";
import { createDastConfig, getDastConfig } from "@/lib/api/dast";

export default function ApiSecurityPage() {
  const { selectedProjectId, status } = useProjectContext();
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [openapi, setOpenapi] = useState("");
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    try {
      const cfg = await getDastConfig(selectedProjectId).catch(() => null);
      setConfig(cfg);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    if (status === "ready" && selectedProjectId) load();
  }, [status, selectedProjectId, load]);

  async function handleValidate() {
    setMsg("");
    try {
      await createDastConfig(selectedProjectId, { profile: "api", openapi_ref: openapi, active_testing_enabled: false });
      setMsg("OpenAPI validated and saved");
      load();
    } catch (e) {
      setMsg(e.message);
    }
  }

  if (status === "loading") return <LoadingState message="Loading..." />;
  if (!selectedProjectId) return <EmptyState title="No project" description="Select project" />;
  if (loading) return <div><PageHeader title="API Security" /><LoadingState message="Loading..." /></div>;
  if (error) return <div><PageHeader title="API Security" /><ErrorState title="Error" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="API Security" description="OpenAPI 3.x ingestion, endpoint discovery, auth-aware testing" />
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">OpenAPI Validation</h3>
        <p className="text-xs text-muted">Checks: missing auth, insecure HTTP, broken auth, excessive exposure, schema violations, missing security schemes, CORS.</p>
        <textarea placeholder="Paste OpenAPI JSON/YAML or reference URL (sanitized, bounded 5000 chars)" value={openapi} onChange={(e) => setOpenapi(e.target.value)} className="mt-2 w-full rounded border bg-canvas p-2 text-xs" rows={6} />
        <button type="button" onClick={handleValidate} className="mt-2 rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Validate & Save</button>
        {msg ? <p className="mt-2 text-xs text-muted">{msg}</p> : null}
        {config?.openapi_ref ? <p className="mt-2 text-xs text-muted">Current: {config.openapi_ref.slice(0,100)}...</p> : null}
      </div>
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Authentication</h3>
        <p className="text-xs text-muted">Bearer, API key, basic, cookie, custom headers — stored via SecretStore (encrypted reference, never returned). UI shows configured/not configured only.</p>
        <p className="mt-1 text-xs text-muted">Auth configured: {config?.auth_configured ? "yes" : "no"}</p>
      </div>
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Evidence</h3>
        <p className="text-xs text-muted">Findings preserve endpoint, method, parameter, payload class, sanitized request/response, scanner provenance. Secrets redacted.</p>
      </div>
    </div>
  );
}
