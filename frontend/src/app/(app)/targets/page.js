"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import LoadingState from "@/components/ui/LoadingState";
import { useProjectContext } from "@/lib/project-context";

function TargetsRedirect() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryProjectId = searchParams.get("project_id") || "";
  const {
    selectedProjectId,
    projects,
    status,
  } = useProjectContext();

  useEffect(() => {
    if (status === "loading") return;
    const projectId =
      queryProjectId || selectedProjectId || projects[0]?.id;
    if (projectId) {
      router.replace(`/projects/${projectId}?tab=targets`);
      return;
    }
    router.replace("/projects");
  }, [
    status,
    queryProjectId,
    selectedProjectId,
    projects,
    router,
  ]);

  return <LoadingState message="Opening project targets..." />;
}

export default function TargetsPage() {
  return (
    <Suspense fallback={<LoadingState message="Opening project targets..." />}>
      <TargetsRedirect />
    </Suspense>
  );
}
