import { api } from "./client";

export function listProjects() {
  return api.get("/api/v1/projects");
}

export function getProject(projectId) {
  return api.get(`/api/v1/projects/${projectId}`);
}

export function createProject(payload) {
  return api.post("/api/v1/projects", payload);
}

export function deleteProject(projectId) {
  return api.delete(`/api/v1/projects/${projectId}`);
}
