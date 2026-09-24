import { describe, expect, it, vi } from "vitest";
import { ApiError, request } from "./client.js";
import { apiError, mockApi } from "../test/fixtures.js";

/**
 * The API client is the only place where a backend failure becomes something
 * an analyst reads. What matters is that it never loses the backend's error
 * `code` (callers branch on it) or the request id (it is how a failure is
 * traced in the server logs), and that it never turns a failure into a
 * success-shaped value.
 */

describe("request", () => {
  it("builds the URL with the /api prefix and drops empty params", async () => {
    const fetchStub = mockApi({ "/alerts": { items: [] } });

    await request("/alerts", { params: { severity: "high", q: "", category: null, limit: 200 } });

    const [url] = fetchStub.mock.calls[0];
    const parsed = new URL(url, "http://localhost");
    expect(parsed.pathname).toBe("/api/alerts");
    expect(parsed.searchParams.get("severity")).toBe("high");
    expect(parsed.searchParams.get("limit")).toBe("200");
    // Empty values must not be sent: the backend validates them and would 422.
    expect(parsed.searchParams.has("q")).toBe(false);
    expect(parsed.searchParams.has("category")).toBe(false);
  });

  it("sends a JSON body with the right header on POST", async () => {
    const fetchStub = mockApi({ "/analyze-alert": { ok: true } });

    await request("/analyze-alert", { method: "POST", body: { alert_id: "ALRT-1003" } });

    const [, init] = fetchStub.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init.body)).toEqual({ alert_id: "ALRT-1003" });
  });

  it("does not set a Content-Type on a GET with no body", async () => {
    const fetchStub = mockApi({ "/alerts": { items: [] } });
    await request("/alerts");
    expect(fetchStub.mock.calls[0][1].headers).toBeUndefined();
  });

  it("preserves the backend error code and request id", async () => {
    mockApi({
      "/analyze-alert": apiError("llm_timeout", "The provider timed out.", {
        status: 504,
        requestId: "abc123",
      }),
    });

    const error = await request("/analyze-alert", { method: "POST", body: {} }).catch((e) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe("llm_timeout");
    expect(error.status).toBe(504);
    expect(error.requestId).toBe("abc123");
  });

  it("replaces API-facing wording with analyst-facing wording", async () => {
    mockApi({
      "/analyze-alert": apiError(
        "llm_unavailable",
        "AI analysis is not available: the LLM provider is not configured.",
      ),
    });

    const error = await request("/analyze-alert", { method: "POST", body: {} }).catch((e) => e);
    expect(error.message).toContain("no LLM API key configured");
  });

  it("keeps the backend message for codes it has no override for", async () => {
    mockApi({ "/alerts": apiError("payload_too_large", "Body exceeds the limit.", { status: 413 }) });

    const error = await request("/alerts").catch((e) => e);
    expect(error.message).toBe("Body exceeds the limit.");
    expect(error.code).toBe("payload_too_large");
  });

  it("falls back to the X-Request-ID header when the body carries no id", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 502,
        headers: { get: (name) => (name === "X-Request-ID" ? "hdr-999" : null) },
        json: async () => {
          throw new Error("not JSON"); // e.g. an nginx error page
        },
      })),
    );

    const error = await request("/alerts").catch((e) => e);
    expect(error.requestId).toBe("hdr-999");
    expect(error.code).toBe("http_error");
    expect(error.message).toContain("502");
  });

  it("reports an unreachable backend as a network error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }));

    const error = await request("/alerts").catch((e) => e);
    expect(error.code).toBe("network_error");
    expect(error.message).toContain("Cannot reach the backend");
  });

  it("turns its own timeout into a timeout error", async () => {
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => {
      // Simulate the browser aborting the request when the timer fires.
      await new Promise((resolve) => setTimeout(resolve, 5));
      const abortError = new Error("aborted");
      abortError.name = "AbortError";
      void init;
      throw abortError;
    }));

    const error = await request("/alerts", { timeoutMs: 1 }).catch((e) => e);
    expect(error.code).toBe("timeout");
  });

  it("rethrows a caller-initiated abort rather than reporting it as a failure", async () => {
    const controller = new AbortController();
    controller.abort();
    vi.stubGlobal("fetch", vi.fn(async () => {
      const abortError = new Error("aborted");
      abortError.name = "AbortError";
      throw abortError;
    }));

    const error = await request("/alerts", { signal: controller.signal }).catch((e) => e);
    // A superseded request is not something to show the analyst.
    expect(error).not.toBeInstanceOf(ApiError);
    expect(error.name).toBe("AbortError");
  });
});
