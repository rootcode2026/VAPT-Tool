/**
 * Playwright global setup (runs once per test run).
 *
 * Responsibilities:
 *   1. Prove the app is reachable — frontend responds and backend /health is
 *      healthy. If not, fail immediately with actionable instructions.
 *   2. Ensure deterministic E2E fixtures exist by running the backend seeder
 *      inside the Docker stack. Set PLAYWRIGHT_SKIP_SEED=1 to skip seeding.
 *
 * The seeding step is safe: it is idempotent, runs only fixture-owned data,
 * and the script itself refuses to run in production environments.
 */
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PROJECT_ROOT = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const FRONTEND_ROOT = path.resolve(fileURLToPath(new URL("../", import.meta.url)));

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || "http://localhost:3000";
const API_URL = process.env.PLAYWRIGHT_API_URL || "http://localhost:8000";

async function waitForUrl(url, { attempts = 20, intervalMs = 1500, expected = 200 } = {}) {
  for (let i = 1; i <= attempts; i += 1) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (res.status === expected) return true;
    } catch {
      // ignore and retry
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return false;
}

function runSeeder() {
  if (process.env.PLAYWRIGHT_SKIP_SEED === "1") {
    console.log("[e2e-setup] PLAYWRIGHT_SKIP_SEED=1 — skipping fixture seeding.");
    return;
  }
  if (!existsSync(path.join(PROJECT_ROOT, "docker-compose.yml"))) {
    throw new Error(
      "[e2e-setup] docker-compose.yml not found at the repository root. " +
        "The E2E suite relies on the local Docker stack for backend + PostgreSQL."
    );
  }
  console.log("[e2e-setup] Seeding deterministic E2E fixtures…");
  execSync(
    "docker compose run --rm --no-deps -e E2E_SEED_ENABLED=true backend " +
      "python scripts/seed_e2e_fixtures.py",
    { cwd: PROJECT_ROOT, stdio: "inherit", timeout: 240_000 }
  );
}

/**
 * Log each fixture user in exactly once and persist a Playwright storageState
 * per user (localStorage token only — no cookies). Tests reuse these files, so
 * the whole suite performs ~7 logins instead of ~50, staying well under the
 * backend's login rate limit (20/min/IP).
 */
async function writeStorageStates() {
  const { apiLogin, USERS, TOKEN_KEY } = await import(
    new URL("./support/helpers.mjs", import.meta.url)
  );
  const stateDir = path.join(FRONTEND_ROOT, "test-results");
  mkdirSync(stateDir, { recursive: true });

  console.log("[e2e-setup] Pre-generating per-user storage states…");
  for (const [key, user] of Object.entries(USERS)) {
    const token = await apiLogin(user.email, user.password);
    writeFileSync(
      path.join(stateDir, `state-${key}.json`),
      JSON.stringify({
        cookies: [],
        origins: [
          {
            origin: BASE_URL,
            localStorage: [{ name: TOKEN_KEY, value: token }],
          },
        ],
      })
    );
    console.log(`[e2e-setup]   state-${key}.json written`);
  }
}

export default async function globalSetup() {
  console.log("[e2e-setup] Verifying application availability…");

  const frontendOk = await waitForUrl(`${BASE_URL}/login`);
  const [backendHealth, backendRaw] = await (async () => {
    try {
      const res = await fetch(`${API_URL}/health`, { signal: AbortSignal.timeout(3000) });
      return [res.status === 200, await res.text()];
    } catch {
      return [false, "unreachable"];
    }
  })();
  const backendOk = backendHealth && backendRaw.includes("healthy");

  if (!frontendOk || !backendOk) {
    const frontendState = frontendOk ? "reachable" : "UNREACHABLE";
    const backendState = backendOk ? "healthy" : "UNHEALTHY/UNREACHABLE";
    throw new Error(
      [
        "[e2e-setup] Application is not available; refusing to run the suite.",
        `  frontend ${BASE_URL}/login  : ${frontendState}`,
        `  backend  ${API_URL}/health  : ${backendState}`,
        "Start the Docker stack first:",
        "  docker compose up -d --build",
        "Then re-run the E2E suite.",
        "To point the suite elsewhere: PLAYWRIGHT_BASE_URL and PLAYWRIGHT_API_URL.",
      ].join("\n")
    );
  }

  console.log("[e2e-setup] Frontend reachable, backend healthy.");
  runSeeder();
  await writeStorageStates();
  console.log("[e2e-setup] Setup complete.");
}