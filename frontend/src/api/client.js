import { API_BASE_URL, REQUEST_TIMEOUT_MS } from "../config.js";

/**
 * An API failure with the backend's stable error `code` attached, so callers
 * can branch on the cause instead of parsing message strings.
 */
export class ApiError extends Error {
  constructor(message, { code = "unknown_error", status = 0, requestId = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

// Fallback copy for codes whose backend message is aimed at API clients rather
// than at an analyst reading a dashboard. The backend message is used as-is
// for anything not listed here.
const MESSAGE_OVERRIDES = {
  llm_unavailable:
    "AI analysis is unavailable: the backend has no LLM API key configured, or the " +
    "provider rejected it.",
  llm_timeout: "The AI provider did not respond in time. The alert was not analysed — try again.",
  llm_provider_error: "The AI provider returned an error. The alert was not analysed.",
  invalid_model_response:
    "The AI returned an invalid assessment and it was rejected. Nothing was recorded.",
  rag_unavailable: "The knowledge base is unavailable, so alerts cannot be analysed right now.",
  database_unavailable: "The database is unavailable. Data may be incomplete — try again shortly.",
  network_error: "Cannot reach the backend. Check that the API is running.",
  timeout: "The request timed out before the backend responded.",
};

function buildUrl(path, params = {}) {
  const url = new URL(`${API_BASE_URL}${path}`, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function toApiError(response) {
  let code = "http_error";
  let message = `Request failed (HTTP ${response.status}).`;
  let requestId = response.headers.get("X-Request-ID");
  try {
    const body = await response.json();
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      requestId = body.error.request_id ?? requestId;
    }
  } catch {
    // Non-JSON error body (e.g. a proxy error page): keep the generic message.
  }
  return new ApiError(MESSAGE_OVERRIDES[code] ?? message, {
    code,
    status: response.status,
    requestId,
  });
}

/** Perform a JSON request. Always rejects with an ApiError. */
export async function request(path, { method = "GET", params, body, signal, timeoutMs } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs ?? REQUEST_TIMEOUT_MS);
  // Abort if either the caller or our own timeout fires.
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort);

  try {
    const response = await fetch(buildUrl(path, params), {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    if (!response.ok) throw await toApiError(response);
    return await response.json();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.name === "AbortError") {
      // A caller-initiated abort is not an error worth showing.
      if (signal?.aborted) throw error;
      throw new ApiError(MESSAGE_OVERRIDES.timeout, { code: "timeout" });
    }
    throw new ApiError(MESSAGE_OVERRIDES.network_error, { code: "network_error" });
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", onAbort);
  }
}
