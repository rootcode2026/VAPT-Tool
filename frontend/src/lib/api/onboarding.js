import { api } from "./client";

export function getOnboardingStatus() {
  return api.get("/api/v1/onboarding/status");
}
export function startOnboarding() {
  return api.post("/api/v1/onboarding/start");
}
export function updateOnboardingStep(step) {
  return api.post("/api/v1/onboarding/progress", { current_step: step });
}
export function skipOnboarding() {
  return api.post("/api/v1/onboarding/skip");
}
export function completeOnboarding() {
  return api.post("/api/v1/onboarding/complete");
}
export function restartOnboarding() {
  return api.post("/api/v1/onboarding/restart");
}
