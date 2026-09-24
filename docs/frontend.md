# Analyst Dashboard

A small SOC triage console: an alert queue on the left, the selected alert and
its AI assessment on the right. React + Vite, no UI framework — the styling is
~600 lines of CSS, which keeps the bundle at ~52 kB gzipped and the look
deliberately plain.

## Design intent

It should read like an internal security tool, not a demo. That means a dense
table, monospace for identifiers and command lines, muted surfaces, and colour
used only to encode severity and verdict. There are no gradients, no cards
floating over hero images, and the only animation is a spinner while a request
is in flight (disabled under `prefers-reduced-motion`).

Colour is always a *secondary* cue. Severity, classification, risk and
confidence are each spelled out in text as well, so the queue stays readable in
greyscale, for colour-blind analysts, and through a screen reader.

## Architecture

```
src/
  config.js              API base URL + timeouts, from environment
  api/client.js          fetch wrapper: query building, timeout, ApiError
  api/alerts.js          one function per endpoint
  hooks/useAlerts.js     queue: debounce, abort, loading/error state
  hooks/useAlertAnalysis.js   stored assessment + "analyse now"
  hooks/useReadiness.js  backend dependency status
  lib/format.js          presentation helpers (bands, timestamps, truncation)
  components/            presentational only
  App.jsx                layout and selection state
```

The rule is that **components receive data and render it**. Requests, retries,
aborts, error mapping and state machines live in `api/` and `hooks/`; filtering
and search are done by the backend, not in the browser. No component computes a
verdict, a risk band from raw evidence, or anything else the backend owns.

`lib/format.js` holds only labels: the risk *bands* mirror the backend's
scoring bands so the wording matches, but the score itself is always the
number the backend returned.

## Views and states

Every asynchronous surface has four states, and each is a distinct component
path rather than a spinner over stale data:

| State | Queue | Assessment |
| --- | --- | --- |
| Loading | "Loading alerts…" | "Checking for a stored assessment…" / "Running analysis" |
| Empty | "No alerts match these filters" + how to clear them | "Not analysed yet" + what the button will do |
| Error | Message, request id, **Try again** | "Analysis failed", message, request id, retry |
| Ready | Table | Full assessment |

**Never a fabricated result.** The assessment panel renders only what the
backend returned. If `/analyze-alert` fails, the panel shows the failure — it
never falls back to a cached, partial or invented verdict. "Not analysed yet"
is a first-class state, not an empty score of zero.

## The assessment display

Shows, in order: classification, risk score and confidence (both as labelled
meters with the number in text), the human-review flag and its reasons, the
recommended action, the reasoning, the evidence list, any unsupported claims
the model declared, backend validation warnings, the retrieved knowledge
chunks with similarity scores (cited ones marked), and a provenance footer
(model, provider, prompt version, time, latency).

Advisory framing is permanent, not a dismissible toast: the header carries
"Advisory only — assessments are AI-generated, must be reviewed by an analyst,
and never trigger containment", and each assessment repeats the human-review
requirement with the backend's own reasons.

## Configuration

Build-time, via Vite (`frontend/.env.example`). These are inlined into the
bundle and visible to anyone loading the page, so **never put a secret here**.

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_API_BASE_URL` | `/api` | Where the browser sends API calls. Same-origin by default, so there is no CORS. |
| `VITE_REQUEST_TIMEOUT_MS` | `15000` | Timeout for ordinary reads. |
| `VITE_ANALYSIS_TIMEOUT_MS` | `120000` | Longer budget for `/analyze-alert`, which is a live LLM call with retries. |
| `VITE_BACKEND_URL` | `http://localhost:8000` | Dev server only: where `npm run dev` proxies `/api`. |

In production nginx serves the built bundle and reverse-proxies `/api/` to the
backend container, so the default works unchanged.

## Error handling

`api/client.js` turns every failure into an `ApiError` carrying the backend's
stable `code`, the HTTP status and the request id. The UI shows a message
written for an analyst (`llm_unavailable` becomes "AI analysis is unavailable:
the backend has no LLM API key configured…") and prints the request id so a
failure can be traced in the server logs. Network failures and timeouts get
their own messages rather than a generic "something went wrong".

When `/health/ready` reports no LLM key, a banner says so up front and the
**Analyse alert** button is disabled — the analyst learns before clicking, not
after a failed request.

## Accessibility

- **Semantics**: a real `<table>` with `<caption>`, `scope`-ed headers and row
  headers; `<button>` for every action; `<label>` bound to every control, with
  `aria-describedby` hints on search and the classification filter.
- **Keyboard**: each row's alert ID is a button, so the queue is fully
  navigable by Tab/Enter. Opening an alert moves focus to the detail heading;
  Escape closes it. Focus outlines are never removed.
- **Screen readers**: loading and empty states are `role="status"`
  (`aria-live="polite"`), errors are `role="alert"`, the analyse button carries
  `aria-busy`, and risk/confidence are `role="meter"` with `aria-valuenow` and
  a descriptive `aria-label`.
- **Contrast**: every foreground token meets WCAG AA (4.5:1) against the
  *lightest* surface it sits on, not just the page background — the difference
  matters, and an axe scan caught three tokens that only passed against the
  darker background.
- **Motion**: the only animation is the spinner, disabled under
  `prefers-reduced-motion`.

`e2e/accessibility.spec.js` runs axe-core (WCAG 2.1 A/AA) against the queue and
the detail view on both viewports and fails on any violation.

## Responsive behaviour

- **≥1100px**: two columns, the detail pane sticky beside the queue. Opening it
  drops the queue's wordiest columns instead of letting every cell wrap.
- **<1100px**: single column; the detail pane becomes a full-screen sheet
  (Escape or the close button returns to the queue).
- **<900px / <620px**: secondary columns (time, category, then host/user) are
  dropped rather than squashed, leaving the triage essentials — ID, severity,
  classification, risk. Below 620px the risk meter gives way to the number
  alone, which is more legible in a narrow column.

A test asserts there is no horizontal page scrolling at any tested viewport.

## Tests

Two suites, deliberately different in what they exercise.

**Component and unit tests** — vitest + Testing Library + jsdom, 123 tests.
`fetch` is stubbed per test, so no backend, database or LLM is involved; that is
what lets them cover states a live backend produces only occasionally (a
timeout, a 503, an analysis still in flight). Co-located with the source as
`*.test.jsx`, with fixtures and the routing fetch stub in `src/test/`.

```bash
npm test                      # vitest run
npm run test:watch
npm run test:coverage
docker compose --profile test run --rm frontend-tests   # no local Node needed
```

Covered: queue rendering including the unanalysed and zero-score cases,
backend-driven filtering and search debouncing, the analysis action end to end,
loading states for both the queue and an in-flight analysis, every error state
(load failure, timeout, provider error, rejected model output, stored-assessment
read failure), the LLM-unavailable banner, and the API client's error mapping.

**End-to-end** — Playwright against a **real backend**, 32 tests across desktop
and mobile viewports:

```bash
cd frontend
npm run test:e2e              # desktop + mobile
npm run test:e2e:desktop
E2E_BASE_URL=http://localhost:8080 npm run test:e2e   # against the Docker stack
```

Covered: queue rendering and required columns, advisory framing, backend search
and each filter, keyboard navigation and focus movement, the un-analysed empty
state, a full analysis (loading → result, with risk/confidence meters and the
queue updating), stored assessments after reload, error handling for both a
dead backend and a failed analysis, no-horizontal-scroll, and the axe audit.

Two notes on how these tests are written:

- Route interception uses **exact path predicates**, not globs. A glob like
  `**/api/alerts**` also matches the dashboard's own `/src/api/alerts.js`
  module under Vite dev, so blocking it blanks the page instead of simulating a
  backend failure.
- Assessments persist, so tests must not assume a pristine database. Anything
  that needs an un-analysed alert asks the queue for one.

Analysis tests skip themselves when `/health/ready` reports no LLM configured,
so the suite still passes against a key-less backend.
