import { ANALYSIS_TIMEOUT_MS } from "../config.js";
import { request } from "./client.js";

/** GET /alerts — filtering and search are applied by the backend. */
export function fetchAlerts({ severity, category, classification, q, limit = 200, offset = 0 } = {},
  signal) {
  return request("/alerts", {
    params: { severity, category, classification, q, limit, offset },
    signal,
  });
}

/** GET /alerts/{id}/analysis — the stored assessment, if one exists. */
export function fetchStoredAnalysis(alertId, signal) {
  return request(`/alerts/${encodeURIComponent(alertId)}/analysis`, { signal });
}

/** POST /analyze-alert — runs a real RAG + LLM analysis. */
export function analyzeAlert(alertId, signal) {
  return request("/analyze-alert", {
    method: "POST",
    body: { alert_id: alertId },
    timeoutMs: ANALYSIS_TIMEOUT_MS,
    signal,
  });
}

/** GET /health/ready — which backend dependencies are available. */
export function fetchReadiness(signal) {
  return request("/health/ready", { signal });
}
