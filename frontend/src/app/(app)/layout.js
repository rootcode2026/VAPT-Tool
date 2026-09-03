"use client";

import { Suspense } from "react";
import AppShell from "@/components/layout/AppShell";
import RequireAuth from "@/components/auth/RequireAuth";
import LoadingState from "@/components/ui/LoadingState";
import { ProjectProvider } from "@/lib/project-context";

export default function AppLayout({ children }) {
  return (
    <Suspense fallback={<LoadingState message="Loading security data..." />}>
      <RequireAuth>
        <ProjectProvider>
          <AppShell>{children}</AppShell>
        </ProjectProvider>
      </RequireAuth>
    </Suspense>
  );
}
