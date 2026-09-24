import { render, screen, waitFor, waitForElementToBeRemoved, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import App from "./App.jsx";
import {
  BENIGN_ALERT,
  SUSPICIOUS_ALERT,
  apiError,
  makeAlert,
  makeAnalysis,
  makeReadiness,
  mockApi,
  mockDashboard,
} from "./test/fixtures.js";

/**
 * Whole-dashboard tests against a stubbed `fetch`.
 *
 * No backend, no database and no LLM is involved: every response is scripted,
 * which is what lets these tests assert on states a live backend would only
 * produce occasionally — a timeout, a 503, a slow analysis still running.
 *
 * Tests that exercise the real backend live in e2e/ (Playwright) and in the
 * backend suite; these cover the browser half of the contract.
 */

const NOT_ANALYSED = apiError("analysis_not_found", "No assessment stored.", { status: 404 });

/**
 * Waits for the initial queue load to finish. "Loading alerts…" is rendered
 * twice while in flight — once by the filter summary, once by the status
 * panel — so the query has to be the plural one.
 */
async function waitForQueue() {
  await waitForElementToBeRemoved(() => screen.queryAllByText("Loading alerts…"));
}

/** Renders the dashboard and waits for the initial load to finish. */
async function renderDashboard(options) {
  const fetchStub = mockDashboard(options);
  render(<App />);
  await waitForQueue();
  return fetchStub;
}

/** Opens the detail pane for one alert. */
async function openAlert(user, alertId) {
  await user.click(screen.getByRole("button", { name: new RegExp(`View alert ${alertId}`) }));
  return within(await screen.findByRole("complementary", { name: "Alert details" }));
}

// --- alert rendering ---------------------------------------------------------

describe("alert rendering", () => {
  it("renders the queue returned by the backend", async () => {
    await renderDashboard({ alerts: [makeAlert(), SUSPICIOUS_ALERT, BENIGN_ALERT] });

    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(screen.getByRole("button", { name: /View alert ALRT-1003/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /View alert ALRT-1031/ })).toBeInTheDocument();
  });

  it("requests the full page of alerts on load", async () => {
    const fetchStub = await renderDashboard();

    const url = new URL(fetchStub.mock.calls.find(([u]) => u.includes("/alerts"))[0],
      "http://localhost");
    expect(url.searchParams.get("limit")).toBe("200");
    expect(url.searchParams.get("offset")).toBe("0");
  });

  it("shows an empty state when the backend returns no alerts", async () => {
    await renderDashboard({ alerts: [] });

    expect(screen.getByText("No alerts match these filters")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows the advisory notice on every load", async () => {
    await renderDashboard();
    expect(screen.getByRole("note")).toHaveTextContent(/advisory only/i);
  });

  it("opens the detail pane with the alert's telemetry", async () => {
    const user = userEvent.setup();
    await renderDashboard({ alerts: [makeAlert()], "/alerts/ALRT-1003/analysis": NOT_ANALYSED });

    const detail = await openAlert(user, "ALRT-1003");

    expect(detail.getByText("SRV-APP-02")).toBeInTheDocument();
    expect(detail.getByText("10.30.2.15")).toBeInTheDocument();
    expect(detail.getByText(/IEX \(New-Object Net.WebClient\)/)).toBeInTheDocument();
  });

  it("closes the detail pane on Escape", async () => {
    const user = userEvent.setup();
    await renderDashboard({ alerts: [makeAlert()], "/alerts/ALRT-1003/analysis": NOT_ANALYSED });
    await openAlert(user, "ALRT-1003");

    await user.keyboard("{Escape}");

    await waitFor(() =>
      expect(screen.queryByRole("complementary", { name: "Alert details" })).not.toBeInTheDocument());
  });
});

// --- filtering ---------------------------------------------------------------

describe("filtering", () => {
  it("sends a severity filter to the backend", async () => {
    const fetchStub = await renderDashboard({ alerts: [makeAlert()] });
    const user = userEvent.setup();

    await user.selectOptions(screen.getByLabelText("Severity"), "critical");

    await waitFor(() => {
      const last = fetchStub.mock.calls.at(-1)[0];
      expect(new URL(last, "http://localhost").searchParams.get("severity")).toBe("critical");
    });
  });

  it("sends a classification filter to the backend", async () => {
    const fetchStub = await renderDashboard({ alerts: [makeAlert()] });
    const user = userEvent.setup();

    await user.selectOptions(screen.getByLabelText("AI classification"), "Malicious");

    await waitFor(() => {
      const last = fetchStub.mock.calls.at(-1)[0];
      expect(new URL(last, "http://localhost").searchParams.get("classification"))
        .toBe("Malicious");
    });
  });

  it("debounces the search box into a single backend query", async () => {
    // Filtering is done by the backend, so an un-debounced search box would
    // fire one request per keystroke.
    const fetchStub = await renderDashboard({ alerts: [makeAlert()] });
    const before = fetchStub.mock.calls.filter(([u]) => u.includes("q=")).length;
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Search"), "powershell");

    await waitFor(() => {
      const searches = fetchStub.mock.calls.filter(([u]) => u.includes("q="));
      expect(searches.length).toBeGreaterThan(before);
      expect(new URL(searches.at(-1)[0], "http://localhost").searchParams.get("q"))
        .toBe("powershell");
    });
    const searches = fetchStub.mock.calls.filter(([u]) => u.includes("q="));
    expect(searches.length).toBeLessThan("powershell".length);
  });

  it("renders whatever the backend returns for a filter, without filtering locally", async () => {
    const fetchStub = mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": ({ searchParams }) =>
        searchParams.get("severity") === "low"
          ? { total: 1, items: [BENIGN_ALERT] }
          : { total: 2, items: [makeAlert(), BENIGN_ALERT] },
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    await user.selectOptions(screen.getByLabelText("Severity"), "low");

    await waitFor(() => {
      const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
      expect(rows).toHaveLength(1);
    });
    expect(screen.getByRole("button", { name: /View alert ALRT-1031/ })).toBeInTheDocument();
    expect(fetchStub).toHaveBeenCalled();
  });

  it("shows the empty state when a filter matches nothing", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": ({ searchParams }) =>
        searchParams.get("severity") ? { total: 0, items: [] } : { total: 1, items: [makeAlert()] },
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    await user.selectOptions(screen.getByLabelText("Severity"), "critical");

    expect(await screen.findByText("No alerts match these filters")).toBeInTheDocument();
  });

  it("restores the full queue when the filters are cleared", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": ({ searchParams }) =>
        searchParams.get("severity") ? { total: 0, items: [] } : { total: 1, items: [makeAlert()] },
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    await user.selectOptions(screen.getByLabelText("Severity"), "critical");
    await screen.findByText("No alerts match these filters");

    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(await screen.findByRole("table")).toBeInTheDocument();
  });
});

// --- loading state -----------------------------------------------------------

describe("loading state", () => {
  it("shows a loading panel before the first response arrives", async () => {
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": async () => { await held; return { total: 0, items: [] }; },
    });

    render(<App />);

    expect(screen.getAllByText("Loading alerts…").length).toBeGreaterThan(0);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();

    release();
    await waitForQueue();
  });

  it("shows a running-analysis state while the request is in flight", async () => {
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
      "/analyze-alert": async () => { await held; return makeAnalysis(); },
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");

    await user.click(await detail.findByRole("button", { name: "Analyse alert" }));

    expect(await screen.findByText("Running analysis")).toBeInTheDocument();
    const button = detail.getByRole("button", { name: /Analysing/ });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    // No verdict may be shown while one is still being produced.
    expect(detail.queryByText("Malicious")).not.toBeInTheDocument();

    release();
    await detail.findByText("Malicious");
  });

  it("checks for a stored assessment before offering to run a new one", async () => {
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": async () => { await held; return makeAnalysis(); },
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    await openAlert(user, "ALRT-1003");

    expect(await screen.findByText("Checking for a stored assessment…")).toBeInTheDocument();

    release();
    await screen.findByText("Malicious");
  });
});

// --- analysis action ---------------------------------------------------------

describe("analysis action", () => {
  it("posts the alert id and renders the returned assessment", async () => {
    const fetchStub = mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
      "/analyze-alert": makeAnalysis(),
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");
    expect(await detail.findByText("Not analysed yet")).toBeInTheDocument();

    await user.click(detail.getByRole("button", { name: "Analyse alert" }));

    // Scoped to the detail pane: "Malicious" is also a filter dropdown option.
    expect(await detail.findByText("Malicious")).toBeInTheDocument();
    expect(detail.getByText("88")).toBeInTheDocument();
    expect(detail.getByText(/SYSTEM-context PowerShell download cradle/)).toBeInTheDocument();

    const analyse = fetchStub.mock.calls.find(([u]) => u.includes("/analyze-alert"));
    expect(analyse[1].method).toBe("POST");
    expect(JSON.parse(analyse[1].body)).toEqual({ alert_id: "ALRT-1003" });
  });

  it("shows a previously stored assessment without re-analysing", async () => {
    const fetchStub = mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert({ latest_classification: "Malicious" })] },
      "/alerts/ALRT-1003/analysis": makeAnalysis({ meta: { cached: true } }),
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    await openAlert(user, "ALRT-1003");

    expect(await screen.findByText("Stored assessment")).toBeInTheDocument();
    expect(fetchStub.mock.calls.some(([u]) => u.includes("/analyze-alert"))).toBe(false);
  });

  it("offers a re-analysis once an assessment exists", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": makeAnalysis(),
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");

    expect(await detail.findByRole("button", { name: "Re-analyse alert" })).toBeInTheDocument();
  });

  it("refreshes the queue verdict after an analysis", async () => {
    let analysed = false;
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": () => ({
        total: 1,
        items: [makeAlert(analysed
          ? { latest_classification: "Malicious", latest_risk_score: 88 }
          : {})],
      }),
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
      "/analyze-alert": () => { analysed = true; return makeAnalysis(); },
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");
    expect(await detail.findByText("Not analysed yet")).toBeInTheDocument();

    await user.click(detail.getByRole("button", { name: "Analyse alert" }));

    const row = within(screen.getByRole("table")).getAllByRole("row")[1];
    await waitFor(() => expect(within(row).getByText("Malicious")).toBeInTheDocument());
  });

  it("disables analysis and says why when the backend has no LLM", async () => {
    mockApi({
      "/health/ready": makeReadiness({ llm_configured: false, status: "degraded" }),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    expect(await screen.findByText("AI analysis is unavailable")).toBeInTheDocument();

    const detail = await openAlert(user, "ALRT-1003");
    expect(detail.getByRole("button", { name: "Analyse alert" })).toBeDisabled();
  });

  it("keeps analysis available when readiness cannot be read", async () => {
    // A failed readiness probe is not evidence that analysis is broken;
    // disabling the button would hide a working feature.
    mockApi({
      "/health/ready": apiError("database_unavailable", "Database is down."),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    const detail = await openAlert(user, "ALRT-1003");

    expect(await detail.findByRole("button", { name: "Analyse alert" })).toBeEnabled();
    expect(screen.queryByText("AI analysis is unavailable")).not.toBeInTheDocument();
  });
});

// --- error state -------------------------------------------------------------

describe("error state", () => {
  it("shows the backend's message and request id when the queue fails to load", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": apiError("database_unavailable", "The database is unavailable.", {
        requestId: "req-abc-123",
      }),
    });
    render(<App />);

    expect(await screen.findByText("Could not load alerts")).toBeInTheDocument();
    expect(screen.getByText(/database is unavailable/i)).toBeInTheDocument();
    expect(screen.getByText("req-abc-123")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("announces a load failure assertively", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": apiError("database_unavailable", "The database is unavailable."),
    });
    render(<App />);

    const panel = await screen.findByRole("alert");
    expect(panel).toHaveAttribute("aria-live", "assertive");
  });

  it("retries the queue when asked", async () => {
    let failed = false;
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": () => {
        if (failed) return { total: 1, items: [makeAlert()] };
        failed = true;
        return apiError("database_unavailable", "The database is unavailable.");
      },
    });
    render(<App />);
    await screen.findByText("Could not load alerts");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("table")).toBeInTheDocument();
  });

  it("reports an unreachable backend", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": () => { throw new TypeError("Failed to fetch"); },
    });
    render(<App />);

    expect(await screen.findByText(/cannot reach the backend/i)).toBeInTheDocument();
  });

  it("reports a failed analysis without inventing a verdict", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
      "/analyze-alert": apiError("llm_provider_error", "The LLM provider returned an error.", {
        status: 502,
      }),
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");

    await user.click(await detail.findByRole("button", { name: "Analyse alert" }));

    expect(await detail.findByText("Analysis failed")).toBeInTheDocument();
    expect(detail.getByText(/provider returned an error/i)).toBeInTheDocument();
    // Nothing that looks like a verdict may appear in the assessment pane.
    for (const verdict of ["Benign", "Suspicious", "Malicious"]) {
      expect(detail.queryByText(verdict)).not.toBeInTheDocument();
    }
    expect(detail.queryByText("Risk score")).not.toBeInTheDocument();
  });

  it("explains an analysis timeout in the analyst's terms", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
      "/analyze-alert": apiError("llm_timeout", "Upstream timed out.", { status: 504 }),
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");

    await user.click(await detail.findByRole("button", { name: "Analyse alert" }));

    expect(await screen.findByText(/did not respond in time/i)).toBeInTheDocument();
    expect(screen.getByText(/the alert was not analysed/i)).toBeInTheDocument();
  });

  it("reports a rejected model response rather than showing it", async () => {
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
      "/analyze-alert": apiError("invalid_model_response", "Schema validation failed.", {
        status: 502,
      }),
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");

    await user.click(await detail.findByRole("button", { name: "Analyse alert" }));

    expect(await screen.findByText(/invalid assessment and it was rejected/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing was recorded/i)).toBeInTheDocument();
  });

  it("lets a failed analysis be retried", async () => {
    let attempted = false;
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": NOT_ANALYSED,
      "/analyze-alert": () => {
        if (attempted) return makeAnalysis();
        attempted = true;
        return apiError("llm_timeout", "Upstream timed out.", { status: 504 });
      },
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();
    const detail = await openAlert(user, "ALRT-1003");
    await user.click(await detail.findByRole("button", { name: "Analyse alert" }));
    await detail.findByText("Analysis failed");

    await user.click(detail.getByRole("button", { name: "Try again" }));

    expect(await detail.findByText("Malicious")).toBeInTheDocument();
  });

  it("surfaces a stored-assessment read failure as an error, not as 'not analysed'", async () => {
    // These are different facts. Showing "not analysed" for a failed read
    // would invite the analyst to overwrite an assessment that does exist.
    mockApi({
      "/health/ready": makeReadiness(),
      "/alerts": { total: 1, items: [makeAlert()] },
      "/alerts/ALRT-1003/analysis": apiError("database_unavailable", "The database is down."),
    });
    render(<App />);
    await waitForQueue();
    const user = userEvent.setup();

    const detail = await openAlert(user, "ALRT-1003");

    expect(await detail.findByText("Analysis failed")).toBeInTheDocument();
    expect(detail.queryByText("Not analysed yet")).not.toBeInTheDocument();
  });
});
