import EmptyState from "@/components/ui/EmptyState";
import PageHeader from "@/components/ui/PageHeader";

export default function AttackSurfacePage() {
  return (
    <div>
      <PageHeader
        title="Attack Surface"
        description="Asset relationships and exposure context will be visualized here."
      />
      <EmptyState
        title="No security data available yet."
        description="Attack-surface mapping will use live asset relationships once that module is implemented."
      />
    </div>
  );
}
