import { useEffect, useRef } from "react";
import { AnalysisPanel } from "./AnalysisPanel.jsx";
import { SeverityBadge } from "./Badge.jsx";
import { ErrorPanel, StatusPanel } from "./StatusPanel.jsx";
import { formatTimestamp } from "../lib/format.js";

/**
 * Detail view for the selected alert: raw telemetry, then the AI assessment.
 *
 * Focus moves to the panel heading on selection so keyboard and screen-reader
 * users land where the new content is, and Escape returns to the list.
 */
export function AlertDetail({ alert, analysis, status, error, onAnalyze, onClose, analysisEnabled }) {
  const headingRef = useRef(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, [alert.alert_id]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const analyzing = status === "analyzing";
  const buttonLabel = analyzing
    ? "Analysing…"
    : analysis ? "Re-analyse alert" : "Analyse alert";

  return (
    <section className="detail" aria-labelledby="detail-heading">
      <header className="detail__header">
        <div>
          <h2 id="detail-heading" ref={headingRef} tabIndex={-1}>
            <span className="mono">{alert.alert_id}</span>
          </h2>
          <p className="detail__subtitle">
            <SeverityBadge severity={alert.severity} />
            <span>{alert.category}</span>
            <span className="muted">{formatTimestamp(alert.timestamp)}</span>
          </p>
        </div>
        <button type="button" className="button button--icon" onClick={onClose}>
          <span aria-hidden="true">✕</span>
          <span className="sr-only">Close alert details</span>
        </button>
      </header>

      <dl className="detail__facts">
        <div><dt>Host</dt><dd className="mono">{alert.hostname}</dd></div>
        <div><dt>User</dt><dd className="mono">{alert.username}</dd></div>
        <div><dt>Source IP</dt><dd className="mono">{alert.source_ip}</dd></div>
        <div><dt>Process</dt><dd className="mono">{alert.process}</dd></div>
      </dl>

      <section className="detail__section">
        <h3>Command line</h3>
        <pre className="command"><code>{alert.command_line}</code></pre>
      </section>

      <section className="detail__section">
        <h3>Detection summary</h3>
        <p>{alert.description}</p>
      </section>

      <section className="detail__section detail__analysis" aria-labelledby="analysis-heading">
        <div className="detail__analysis-head">
          <h3 id="analysis-heading">AI assessment</h3>
          <button
            type="button"
            className="button button--primary"
            onClick={onAnalyze}
            disabled={analyzing || !analysisEnabled}
            aria-busy={analyzing}
            title={analysisEnabled ? undefined : "AI analysis is unavailable — see the banner above"}
          >
            {analyzing && <span className="spinner spinner--button" aria-hidden="true" />}
            {buttonLabel}
          </button>
        </div>

        {status === "loading" && (
          <StatusPanel variant="loading" title="Checking for a stored assessment…" />
        )}

        {analyzing && (
          <StatusPanel variant="loading" title="Running analysis">
            <p>
              Retrieving related security knowledge and asking the model for an assessment.
              This usually takes a few seconds.
            </p>
          </StatusPanel>
        )}

        {status === "none" && (
          <StatusPanel variant="empty" title="Not analysed yet">
            <p>
              This alert has no stored assessment. Select <strong>Analyse alert</strong> to run
              one — the result comes from the backend model, and is saved for review.
            </p>
          </StatusPanel>
        )}

        {status === "error" && (
          <ErrorPanel error={error} onRetry={onAnalyze} title="Analysis failed" />
        )}

        {status === "ready" && analysis && <AnalysisPanel analysis={analysis} />}
      </section>
    </section>
  );
}
