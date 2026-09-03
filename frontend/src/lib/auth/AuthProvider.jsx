"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { apiRequest, ApiError, setUnauthorizedHandler } from "@/lib/api/client";
import { clearAccessToken, getAccessToken, setAccessToken } from "@/lib/auth/token";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [status, setStatus] = useState("loading");
  const [user, setUser] = useState(null);

  const clearSession = useCallback(() => {
    clearAccessToken();
    setUser(null);
    setStatus("unauthenticated");
  }, []);

  const loadSession = useCallback(async () => {
    const token = getAccessToken();
    if (!token) {
      setUser(null);
      setStatus("unauthenticated");
      return;
    }

    try {
      const profile = await apiRequest("/api/v1/auth/me", {
        authRedirect: false,
      });
      setUser(profile);
      setStatus("authenticated");
    } catch {
      clearAccessToken();
      setUser(null);
      setStatus("unauthenticated");
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(clearSession);
    return () => setUnauthorizedHandler(null);
  }, [clearSession]);

  useEffect(() => {
    const id = window.setTimeout(() => {
      loadSession();
    }, 0);
    return () => window.clearTimeout(id);
  }, [loadSession]);

  const login = useCallback(async (email, password) => {
    const result = await apiRequest("/api/v1/auth/login", {
      method: "POST",
      body: { email, password },
      auth: false,
      authRedirect: false,
    });

    setAccessToken(result.access_token);
    setUser(result.user);
    setStatus("authenticated");
    return result.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiRequest("/api/v1/auth/logout", {
        method: "POST",
        authRedirect: false,
      });
    } catch {
      // Client session is cleared regardless of server response.
    } finally {
      clearSession();
    }
  }, [clearSession]);

  const value = useMemo(
    () => ({
      status,
      user,
      isAuthenticated: status === "authenticated",
      login,
      logout,
      clearSession,
      refresh: loadSession,
    }),
    [status, user, login, logout, clearSession, loadSession]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

export { ApiError };
