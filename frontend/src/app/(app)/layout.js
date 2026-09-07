"use client";

import { Suspense } from "react";
import AppShell from "@/components/layout/AppShell";
import RequireAuth from "@/components/auth/RequireAuth";
import LoadingState from "@/components/ui/LoadingState";
import { ProjectProvider } from "@/lib/project-context";
import { TourProvider } from "@/components/onboarding/TourProvider";
import TourOverlay from "@/components/onboarding/TourOverlay";
import WelcomeModal from "@/components/onboarding/WelcomeModal";

export default function AppLayout({ children }) {
  return (
    <Suspense fallback={<LoadingState message="Loading security data..." />}>
      <RequireAuth>
        <ProjectProvider>
          <TourProvider>
            <AppShell>{children}</AppShell>
            <TourOverlay />
            <WelcomeModal />
          </TourProvider>
        </ProjectProvider>
      </RequireAuth>
    </Suspense>
  );
}
