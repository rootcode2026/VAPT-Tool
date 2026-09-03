import EmptyState from "@/components/ui/EmptyState";
import PageHeader from "@/components/ui/PageHeader";

export default function AssetsPage() {
  return (
    <div>
      <PageHeader
        title="Assets"
        description="Discovered assets and metadata will be listed here from the assets API."
      />
      <EmptyState
        title="No security data available yet."
        description="Asset inventory, relationships, and metadata will be connected in a later frontend module."
      />
    </div>
  );
}
