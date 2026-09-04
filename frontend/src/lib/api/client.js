import { clearAccessToken, getAccessToken } from "@/lib/auth/token";

export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
).replace(/\/$/, "");

export class ApiError extends Error {
  constructor(message, { status, details, code } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status ?? 0;
    this.details = details ?? null;
    this.code = code ?? null;
  }
}

let unauthorizedHandler = null;
let redirectingToLogin = false;

export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler;
}

export function redirectToLogin(nextPath) {
  if (typeof window === "undefined" || redirectingToLogin) {
    return;
  }

  const current =
    nextPath ||
    `${window.location.pathname}${window.location.search}`;

  if (current.startsWith("/login")) {
    return;
  }

  redirectingToLogin = true;
  const target = `${window.location.origin}/login?next=${encodeURIComponent(current)}`;
  // Hard navigation clears in-memory state and prevents 401 redirect loops.
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- session reset
  window.location.assign(target);
}

function publicErrorMessage(status, data) {
  const detail =
    (typeof data === "object" && data?.detail) ||
    (typeof data === "string" ? data : null);

  if (status === 401) {
    if (detail === "Invalid email or password.") {
      return "Invalid email or password.";
    }
    return "Your session has expired. Please sign in again.";
  }

  if (status === 403) {
    return "You are not authorized to view this resource.";
  }

  if (status >= 500) {
    return "Unable to load security data.";
  }

  if (typeof detail === "string" && detail && !/traceback|sqlalchemy|psycopg|stack/i.test(detail)) {
    return detail;
  }

  return "Unable to load security data.";
}

async function parseBody(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function buildHeaders({ body, headers, auth, token }) {
  const next = {
    Accept: "application/json",
    ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    ...headers,
  };

  if (auth !== false && token) {
    next.Authorization = `Bearer ${token}`;
  }

  return next;
}

export async function apiRequest(path, options = {}) {
  const {
    method = "GET",
    query,
    body,
    headers,
    cache = "no-store",
    auth = true,
    authRedirect = true,
  } = options;

  const token = auth === false ? null : getAccessToken();

  const url = new URL(
    path.startsWith("http") ? path : `${API_BASE_URL}${path}`
  );

  if (query) {
    Object.entries(query).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    });
  }

  let response;

  try {
    response = await fetch(url.toString(), {
      method,
      cache,
      headers: buildHeaders({ body, headers, auth, token }),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Unable to connect to the security service.", {
      status: 0,
      code: "network",
    });
  }

  const data = await parseBody(response);

  // Global expired-session handling: 401 on a protected request → clear session + redirect to login
  // - Only for authenticated requests (auth !== false) to avoid redirecting public 401s
  // - Respect authRedirect flag to allow callers like login to suppress redirect
  // - Do not redirect for auth routes themselves (e.g., login 401 for invalid credentials)
  if (response.status === 401 && auth !== false && authRedirect) {
    const urlString = url.toString();
    const isAuthRoute = urlString.includes("/api/v1/auth/");
    if (!isAuthRoute) {
      clearAccessToken();
      if (unauthorizedHandler) {
        unauthorizedHandler();
      }
      redirectToLogin();
    }
  }

  if (!response.ok) {
    throw new ApiError(publicErrorMessage(response.status, data), {
      status: response.status,
      details: data,
    });
  }

  return data;
}

export async function apiFetch(input, init = {}) {
  const { auth = true, authRedirect = true, ...fetchInit } = init;
  const token = auth === false ? null : getAccessToken();
  const headers = new Headers(fetchInit.headers || {});

  if (auth !== false && token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response;

  try {
    response = await fetch(input, { ...fetchInit, headers });
  } catch (error) {
    throw error;
  }

  // Global 401 handling for apiFetch — same semantics as apiRequest
  if (response.status === 401 && auth !== false && authRedirect) {
    const url = typeof input === "string" ? input : input?.url;
    const isAuthRoute = typeof url === "string" && url.includes("/api/v1/auth/");
    if (!isAuthRoute) {
      clearAccessToken();
      if (unauthorizedHandler) {
        unauthorizedHandler();
      }
      redirectToLogin();
    }
  }

  return response;
}

export const api = {
  get: (path, options) => apiRequest(path, { ...options, method: "GET" }),
  post: (path, body, options) =>
    apiRequest(path, { ...options, method: "POST", body }),
  put: (path, body, options) =>
    apiRequest(path, { ...options, method: "PUT", body }),
  patch: (path, body, options) =>
    apiRequest(path, { ...options, method: "PATCH", body }),
  delete: (path, options) => apiRequest(path, { ...options, method: "DELETE" }),
};
