// Backend location. Defaults to the same-origin "/api" prefix, which both the
// Vite dev proxy and the production nginx config reverse-proxy to the backend.
// Override with VITE_API_BASE_URL to point at a backend on another host.
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "/api").replace(/\/$/, "");

// Analysis is a live LLM call: allow for retries and a slow provider.
export const ANALYSIS_TIMEOUT_MS = Number(import.meta.env.VITE_ANALYSIS_TIMEOUT_MS ?? 120000);
export const REQUEST_TIMEOUT_MS = Number(import.meta.env.VITE_REQUEST_TIMEOUT_MS ?? 15000);
