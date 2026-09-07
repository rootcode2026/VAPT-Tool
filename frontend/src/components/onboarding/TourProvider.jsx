"use client";

/* eslint-disable */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth/AuthProvider";
import { getTourSteps } from "@/lib/tourSteps";
import {
  getOnboardingStatus,
  startOnboarding,
  updateOnboardingStep,
  skipOnboarding,
  completeOnboarding,
  restartOnboarding,
} from "@/lib/api/onboarding";

const TourContext = createContext(null);

export function TourProvider({ children }) {
  const { user, isAuthenticated } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const [status, setStatus] = useState(null);
  const [active, setActive] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [showWelcome, setShowWelcome] = useState(false);
  const [loading, setLoading] = useState(true);

  const steps = useMemo(() => (user ? getTourSteps(user) : []), [user]);

  const load = useCallback(async () => {
    if (!isAuthenticated || !user) {
      setLoading(false);
      return;
    }
    try {
      const s = await getOnboardingStatus();
      setStatus(s);
      // If not_started and not on login page, show welcome
      if (s.status === "not_started") {
        setShowWelcome(true);
      } else if (s.status === "in_progress") {
        setStepIndex(Math.min(s.current_step || 0, steps.length - 1));
        setActive(true);
      }
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [isAuthenticated, user, steps.length]);

  useEffect(() => {
    load();
  }, [load]);

  const start = useCallback(async () => {
    try {
      const s = await startOnboarding();
      setStatus(s);
      setStepIndex(0);
      setActive(true);
      setShowWelcome(false);
    } catch {}
  }, []);

  const skip = useCallback(async () => {
    try {
      const s = await skipOnboarding();
      setStatus(s);
      setActive(false);
      setShowWelcome(false);
    } catch {}
  }, []);

  const next = useCallback(async () => {
    const nextIdx = stepIndex + 1;
    if (nextIdx >= steps.length) {
      try {
        const s = await completeOnboarding();
        setStatus(s);
      } catch {}
      setActive(false);
      return;
    }
    setStepIndex(nextIdx);
    try {
      await updateOnboardingStep(nextIdx);
    } catch {}
    const nextStep = steps[nextIdx];
    if (nextStep?.href && nextStep.href !== pathname) {
      router.push(nextStep.href);
    }
  }, [stepIndex, steps, pathname, router]);

  const back = useCallback(async () => {
    const prev = Math.max(0, stepIndex - 1);
    setStepIndex(prev);
    try {
      await updateOnboardingStep(prev);
    } catch {}
    const prevStep = steps[prev];
    if (prevStep?.href && prevStep.href !== pathname) {
      router.push(prevStep.href);
    }
  }, [stepIndex, steps, pathname, router]);

  const close = useCallback(async () => {
    setActive(false);
    try {
      await updateOnboardingStep(stepIndex);
    } catch {}
  }, [stepIndex]);

  const restart = useCallback(async () => {
    try {
      const s = await restartOnboarding();
      setStatus(s);
      setStepIndex(0);
      setActive(true);
      setShowWelcome(false);
      router.push("/dashboard");
    } catch {}
  }, [router]);

  // Keyboard handling
  useEffect(() => {
    if (!active) return;
    const onKey = (e) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active, close]);

  // Persist step on refresh via last_seen
  useEffect(() => {
    if (!active) return;
    const handler = () => {
      try {
        updateOnboardingStep(stepIndex);
      } catch {}
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [active, stepIndex]);

  const value = useMemo(
    () => ({
      status,
      steps,
      stepIndex,
      currentStep: steps[stepIndex] || null,
      active,
      showWelcome,
      loading,
      start,
      skip,
      next,
      back,
      close,
      restart,
      setShowWelcome,
    }),
    [status, steps, stepIndex, active, showWelcome, loading, start, skip, next, back, close, restart]
  );

  return <TourContext.Provider value={value}>{children}</TourContext.Provider>;
}

export function useTour() {
  const ctx = useContext(TourContext);
  if (!ctx) throw new Error("useTour must be used within TourProvider");
  return ctx;
}
