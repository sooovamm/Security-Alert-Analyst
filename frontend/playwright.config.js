import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end tests run against the real dashboard and a real backend — no
 * mocked API. Start both first:
 *
 *   cd backend && uvicorn app.main:app --port 8010
 *   cd frontend && VITE_BACKEND_URL=http://127.0.0.1:8010 npm run dev
 *
 * Analysis tests need the backend to have an LLM configured; they skip
 * themselves when /health/ready reports it is not.
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 60000,
  expect: { timeout: 10000 },
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:5173",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "mobile", use: { ...devices["Pixel 5"] } },
  ],
});
