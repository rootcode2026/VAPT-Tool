import { api } from "./client";

export function login(email, password) {
  return api.post(
    "/api/v1/auth/login",
    { email, password },
    { auth: false, authRedirect: false }
  );
}

export function getCurrentUser() {
  return api.get("/api/v1/auth/me", { authRedirect: false });
}

export function logout() {
  return api.post("/api/v1/auth/logout", undefined, { authRedirect: false });
}
