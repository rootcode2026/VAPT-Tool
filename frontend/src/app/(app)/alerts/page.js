"use client";

import PageHeader from "@/components/ui/PageHeader";
import ProjectSelect from "@/components/layout/ProjectSelect";
import { AlertsPanel } from "@/components/alerts/AlertsPanel";
import { useProjectContext } from "@/lib/project-context";

export default function AlertsPage() {
  const { selectedProjectId } = useProjectContext();

  return (
    <div className="space-y-4">
      <PageHeader
        title="Alerts"
        description="Operational signals from monitored changes. Acknowledge or resolve alerts; notification delivery is configured per project."
        actions={<ProjectSelect />}
      />
      <AlertsPanel projectId={selectedProjectId} />
    </div>
  );
}
