import { expect, test } from "@playwright/test";

const QUEUE = "table";

// Match the API path exactly. A glob such as "**/api/alerts**" would also match
// the dashboard's own /src/api/alerts.js module under Vite dev, and blocking
// that blanks the page instead of exercising a backend failure.
const isAlertsRequest = (url) => url.pathname === "/api/alerts";
const isAnalyzeRequest = (url) => url.pathname === "/api/analyze-alert";
const isReadinessRequest = (url) => url.pathname === "/api/health/ready";

/** The alert queue region — scopes queries away from page-level banners. */
const queue = (page) => page.getByRole("region", { name: "Alert queue" });

/**
 * Opens an alert that has no stored assessment. Assessments persist in the
 * backend, so a run must not assume a pristine database — earlier runs (or a
 * demo) may already have analysed the first row.
 */
async function openUnanalysedAlert(page) {
  const row = page.locator(`${QUEUE} tbody tr`, { hasText: "Not analysed" }).first();
  if (!(await row.count())) test.skip(true, "every alert already has a stored assessment");
  const button = row.getByRole("button");
  const alertId = (await button.textContent()).replace("View alert ", "").trim();
  await button.click();
  return alertId;
}

async function llmConfigured(request, baseURL) {
  const response = await request.get(`${baseURL}/api/health/ready`);
  return (await response.json()).llm_configured;
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
});

test("shows the triage queue with the required columns", async ({ page }) => {
  // Always visible, at every width: the triage essentials.
  for (const column of ["Alert ID", "Severity", "AI classification", "Risk"]) {
    await expect(page.getByRole("columnheader", { name: column })).toBeVisible();
  }

  // Secondary columns are dropped on narrow viewports rather than squashed.
  const narrow = (page.viewportSize()?.width ?? 0) < 900;
  const category = page.getByRole("columnheader", { name: "Category" });
  await (narrow ? expect(category).toBeHidden() : expect(category).toBeVisible());

  await expect(page.locator(`${QUEUE} tbody tr`)).toHaveCount(45);
  await expect(page.getByText("45 alerts")).toBeVisible();
});

test("layout fits the viewport without sideways scrolling", async ({ page }) => {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});

test("states the assessment is advisory", async ({ page }) => {
  await expect(page.getByRole("note")).toContainText(/advisory only/i);
  await expect(page.getByRole("note")).toContainText(/reviewed by an analyst/i);
});

test("search filters the queue through the backend", async ({ page }) => {
  const search = page.getByRole("searchbox", { name: "Search" });
  await search.fill("mimikatz");
  await expect(page.locator(`${QUEUE} tbody tr`)).not.toHaveCount(45);
  await expect(page.locator(`${QUEUE} tbody tr`).first()).toContainText(/mimikatz/i);

  await search.fill("zzz-nothing-matches");
  // Scoped to the queue: the "AI analysis is unavailable" banner is also a
  // role=status, so an unscoped query is ambiguous when no LLM is configured.
  await expect(queue(page).getByRole("status")).toContainText("No alerts match these filters");
  await expect(page.locator(QUEUE)).toHaveCount(0);

  await page.getByRole("button", { name: "Clear filters" }).click();
  await expect(page.locator(`${QUEUE} tbody tr`)).toHaveCount(45);
});

test("filters by severity and category", async ({ page }) => {
  await page.getByLabel("Severity").selectOption("critical");
  const rows = page.locator(`${QUEUE} tbody tr`);
  await expect(rows.first()).toBeVisible();
  const count = await rows.count();
  expect(count).toBeLessThan(45);
  for (let i = 0; i < count; i += 1) {
    await expect(rows.nth(i)).toContainText(/critical/i);
  }

  await page.getByLabel("Category").selectOption("Brute-force Authentication");
  await expect(page.getByText(/\d+ alerts matching filters/)).toBeVisible();
  await expect(page.locator(`${QUEUE} tbody tr`).first())
    .toContainText("Brute-force Authentication");
});

test("opens alert details from the keyboard", async ({ page }) => {
  const firstAlert = page.locator(`${QUEUE} tbody tr`).first().getByRole("button");
  const alertId = (await firstAlert.textContent()).replace("View alert ", "").trim();

  await firstAlert.focus();
  await page.keyboard.press("Enter");

  const detail = page.getByRole("complementary", { name: "Alert details" });
  await expect(detail).toBeVisible();
  await expect(detail.getByRole("heading", { level: 2 })).toContainText(alertId);
  // focus moves to the panel so keyboard users land on the new content
  await expect(detail.getByRole("heading", { level: 2 })).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(detail).toBeHidden();
});

test("shows an empty state for an alert that has not been analysed", async ({ page, request, baseURL }) => {
  await openUnanalysedAlert(page);
  const detail = page.getByRole("complementary", { name: "Alert details" });
  await expect(detail.getByText("Not analysed yet")).toBeVisible();
  // no verdict is shown before the backend has produced one
  await expect(detail.getByText("Risk score")).toHaveCount(0);

  // The control is offered only when the backend can actually analyse. Both
  // states are correct; which one applies is the backend's to decide.
  const analyse = detail.getByRole("button", { name: "Analyse alert" });
  await (await llmConfigured(request, baseURL)
    ? expect(analyse).toBeEnabled()
    : expect(analyse).toBeDisabled());
});

test("analyses an alert and renders the backend result", async ({ page, request, baseURL }) => {
  test.skip(!(await llmConfigured(request, baseURL)), "backend has no LLM configured");

  // Delay the real request (not a fake response) so the loading state is
  // observable deterministically; the assessment still comes from the backend.
  await page.route(isAnalyzeRequest, async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 2500));
    await route.continue();
  });

  const alertId = await openUnanalysedAlert(page);
  const detail = page.getByRole("complementary", { name: "Alert details" });
  const analyse = detail.getByRole("button", { name: "Analyse alert" });

  await analyse.click();
  // While in flight: explicit loading panel, and the button is busy + disabled.
  await expect(detail.getByText("Running analysis")).toBeVisible();
  const busy = detail.getByRole("button", { name: "Analysing…" });
  await expect(busy).toBeDisabled();
  await expect(busy).toHaveAttribute("aria-busy", "true");

  await expect(detail.getByRole("heading", { name: "Recommended action" })).toBeVisible({ timeout: 30000 });
  await expect(detail.getByRole("heading", { name: "Reasoning" })).toBeVisible();
  await expect(detail.getByRole("heading", { name: "Evidence" })).toBeVisible();
  await expect(detail.getByRole("heading", { name: "Retrieved knowledge" })).toBeVisible();

  // risk + confidence are exposed as meters with real values
  const meters = detail.getByRole("meter");
  await expect(meters).toHaveCount(2);
  const risk = await meters.first().getAttribute("aria-valuenow");
  expect(Number(risk)).toBeGreaterThanOrEqual(0);
  expect(Number(risk)).toBeLessThanOrEqual(100);

  await expect(detail.getByText(/Human review required/)).toBeVisible();
  await expect(detail.getByRole("button", { name: "Re-analyse alert" })).toBeVisible();

  // the queue row for this alert picks up the new verdict
  await expect(page.locator(`${QUEUE} tbody tr`, { hasText: alertId }).first())
    .toContainText(/Malicious|Suspicious|Benign/);
});

test("stored assessment is served without re-analysing", async ({ page, request, baseURL }) => {
  test.skip(!(await llmConfigured(request, baseURL)), "backend has no LLM configured");

  // analyse one alert, then reload and reopen it
  const alertId = await openUnanalysedAlert(page);
  const detail = page.getByRole("complementary", { name: "Alert details" });
  await detail.getByRole("button", { name: "Analyse alert" }).click();
  await expect(detail.getByRole("heading", { name: "Recommended action" })).toBeVisible({ timeout: 30000 });

  await page.reload();
  await page.getByRole("button", { name: `View alert ${alertId}` }).click();
  await expect(page.getByText("Stored assessment")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recommended action" })).toBeVisible();
});

test("classification filter uses stored verdicts", async ({ page, request, baseURL }) => {
  test.skip(!(await llmConfigured(request, baseURL)), "backend has no LLM configured");

  await page.getByLabel("AI classification").selectOption("Malicious");
  const rows = page.locator(`${QUEUE} tbody tr`);
  const count = await rows.count();
  for (let i = 0; i < count; i += 1) {
    await expect(rows.nth(i)).toContainText("Malicious");
  }
});

test("degraded retrieval is shown as failed, not as absent evidence", async ({ page, request, baseURL }) => {
  test.skip(!(await llmConfigured(request, baseURL)), "backend has no LLM configured");

  // The backend degrades when retrieval breaks: the assessment still arrives,
  // but the UI must say there was no evidence behind it.
  await page.route(isAnalyzeRequest, async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.retrieval = {
      status: "failed",
      sufficient: false,
      note: "Knowledge retrieval failed, so no internal security knowledge was available.",
      documents: [],
      similarity_scores: [],
      cited_chunk_ids: [],
    };
    body.assessment.knowledge_sufficient = false;
    await route.fulfill({ response, json: body });
  });

  await page.locator(`${QUEUE} tbody tr`).first().getByRole("button").click();
  const detail = page.getByRole("complementary", { name: "Alert details" });
  const analyse = detail.getByRole("button", { name: /Analyse alert|Re-analyse alert/ });
  await expect(analyse).toBeEnabled();
  await analyse.click();

  await expect(detail.getByText(/Knowledge retrieval unavailable/i)).toBeVisible();
  await expect(detail.getByText(/no supporting evidence to show/i)).toBeVisible();
  // and no evidence list is fabricated
  await expect(detail.locator(".list--knowledge")).toHaveCount(0);
});


test("surfaces a backend failure as a readable error", async ({ page }) => {
  await page.route(isAlertsRequest, (route) => route.abort("failed"));
  await page.reload();

  const error = page.getByRole("alert");
  await expect(error).toContainText("Could not load alerts");
  await expect(error).toContainText(/cannot reach the backend/i);
  await expect(page.getByRole("button", { name: "Try again" })).toBeVisible();
});

test("reports an analysis failure without inventing a result", async ({ page }) => {
  // This checks how a failure is rendered, which needs no working LLM — only
  // a dashboard that offers the control. Readiness is reported as configured
  // so the test covers the same ground whether or not a key is present.
  await page.route(isReadinessRequest, async (route) => {
    const response = await route.fetch();
    await route.fulfill({
      response,
      json: { ...(await response.json()), llm_configured: true },
    });
  });
  await page.reload();
  await expect(page.getByRole("table")).toBeVisible();

  await page.route(isAnalyzeRequest, (route) =>
    route.fulfill({
      status: 504,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "llm_timeout", message: "timeout", request_id: "abc123" },
      }),
    }));

  await page.locator(`${QUEUE} tbody tr`).first().getByRole("button").click();
  const detail = page.getByRole("complementary", { name: "Alert details" });
  // Let the panel finish loading any stored assessment first: clicking while it
  // is still resolving races the re-render.
  const analyse = detail.getByRole("button", { name: /Analyse alert|Re-analyse alert/ });
  await expect(analyse).toBeEnabled();
  await analyse.click();

  const error = detail.getByRole("alert");
  await expect(error).toContainText("Analysis failed");
  await expect(error).toContainText(/did not respond in time/i);
  await expect(error).toContainText("abc123");   // request id for log correlation
  await expect(detail.getByRole("heading", { name: "Recommended action" })).toHaveCount(0);
});
