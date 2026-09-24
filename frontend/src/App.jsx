import { useCallback, useMemo, useState } from "react";
import { AlertDetail } from "./components/AlertDetail.jsx";
import { AlertTable } from "./components/AlertTable.jsx";
import { FilterBar } from "./components/FilterBar.jsx";
import { ErrorPanel, StatusPanel } from "./components/StatusPanel.jsx";
import { useAlertAnalysis } from "./hooks/useAlertAnalysis.js";
import { useAlerts } from "./hooks/useAlerts.js";
import { useReadiness } from "./hooks/useReadiness.js";

const EMPTY_FILTERS = { q: "", severity: "", classification: "", category: "" };

export default function App() {
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [selectedId, setSelectedId] = useState(null);

  const { alerts, total, status, error, retry, refreshQuietly } = useAlerts(filters);
  const readiness = useReadiness();

  // Keep the verdict columns in step with a newly stored assessment.
  const onAnalysed = useCallback(() => refreshQuietly(), [refreshQuietly]);
  const analysis = useAlertAnalysis(selectedId, { onAnalysed });

  const selectedAlert = useMemo(
    () => alerts.find((alert) => alert.alert_id === selectedId) ?? null,
    [alerts, selectedId],
  );

  const analysisEnabled = readiness ? readiness.llm_configured : true;

  return (
    <div className="app">
      <header className="app__header">
        <div className="app__brand">
          <h1>Security Alert Analyst</h1>
          <p className="app__tagline">SOC triage console</p>
        </div>
        <p className="advisory" role="note">
          <strong>Advisory only.</strong> Assessments are AI-generated, must be reviewed by an
          analyst, and never trigger containment.
        </p>
      </header>

      {readiness && !readiness.llm_configured && (
        <div className="app__banner">
          <StatusPanel variant="warning" title="AI analysis is unavailable">
            <p>
              The backend has no LLM API key configured. Alerts and previously stored
              assessments are still available to review.
            </p>
          </StatusPanel>
        </div>
      )}

      <main className={`app__main ${selectedAlert ? "app__main--split" : ""}`}>
        <section className="queue" aria-label="Alert queue">
          <FilterBar
            filters={filters}
            onChange={setFilters}
            onReset={() => setFilters(EMPTY_FILTERS)}
            resultCount={alerts.length}
            totalCount={total}
            busy={status === "loading"}
          />

          {status === "loading" && <StatusPanel variant="loading" title="Loading alerts…" />}

          {status === "error" && (
            <ErrorPanel error={error} onRetry={retry} title="Could not load alerts" />
          )}

          {status === "ready" && alerts.length === 0 && (
            <StatusPanel variant="empty" title="No alerts match these filters">
              <p>Adjust the search term or clear the filters to see the full queue.</p>
            </StatusPanel>
          )}

          {status === "ready" && alerts.length > 0 && (
            <AlertTable alerts={alerts} selectedId={selectedId} onSelect={setSelectedId} />
          )}
        </section>

        {selectedAlert && (
          <aside className="detail-pane" aria-label="Alert details">
            <AlertDetail
              alert={selectedAlert}
              analysis={analysis.analysis}
              status={analysis.status}
              error={analysis.error}
              onAnalyze={analysis.runAnalysis}
              onClose={() => setSelectedId(null)}
              analysisEnabled={analysisEnabled}
            />
          </aside>
        )}
      </main>
    </div>
  );
}
