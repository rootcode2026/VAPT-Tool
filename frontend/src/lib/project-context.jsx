"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { listProjects } from "@/lib/api/projects";

const STORAGE_KEY = "vapt.selectedProjectId";
const ProjectContext = createContext(null);

export function ProjectProvider({ children }) {
  const [projects, setProjects] = useState([]);
  const [selectedProjectId, setSelectedProjectIdState] = useState("");
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState("");

  const loadProjects = useCallback(async (options = {}) => {
    const silent = options.silent === true;
    if (!silent) {
      setStatus("loading");
    }
    setError("");
    try {
      const items = await listProjects();
      const list = Array.isArray(items) ? items : [];
      setProjects(list);

      setSelectedProjectIdState((current) => {
        const stored =
          typeof window !== "undefined"
            ? window.sessionStorage.getItem(STORAGE_KEY)
            : "";
        const preferred = current || stored;
        const next =
          preferred && list.some((project) => project.id === preferred)
            ? preferred
            : list[0]?.id || "";
        if (typeof window !== "undefined") {
          if (next) {
            window.sessionStorage.setItem(STORAGE_KEY, next);
          } else {
            window.sessionStorage.removeItem(STORAGE_KEY);
          }
        }
        return next;
      });
      setStatus("ready");
    } catch (err) {
      setProjects([]);
      setSelectedProjectIdState("");
      setError(err.message || "Unable to load security data.");
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    const id = window.setTimeout(() => {
      loadProjects();
    }, 0);
    return () => window.clearTimeout(id);
  }, [loadProjects]);

  const setSelectedProjectId = useCallback((projectId) => {
    setSelectedProjectIdState(projectId);
    if (typeof window !== "undefined") {
      if (projectId) {
        window.sessionStorage.setItem(STORAGE_KEY, projectId);
      } else {
        window.sessionStorage.removeItem(STORAGE_KEY);
      }
    }
  }, []);

  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) || null,
    [projects, selectedProjectId]
  );

  const value = useMemo(
    () => ({
      projects,
      selectedProjectId,
      selectedProject,
      setSelectedProjectId,
      status,
      error,
      refreshProjects: loadProjects,
    }),
    [
      projects,
      selectedProjectId,
      selectedProject,
      setSelectedProjectId,
      status,
      error,
      loadProjects,
    ]
  );

  return (
    <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>
  );
}

export function useProjectContext() {
  const context = useContext(ProjectContext);
  if (!context) {
    throw new Error("useProjectContext must be used within ProjectProvider");
  }
  return context;
}
