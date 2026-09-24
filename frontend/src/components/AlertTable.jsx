import { ClassificationBadge, SeverityBadge } from "./Badge.jsx";
import { RiskScoreBar } from "./RiskScore.jsx";
import { formatTimestamp, truncate } from "../lib/format.js";

/**
 * The triage queue.
 *
 * A real table (not divs) so screen readers announce row/column context and
 * the browser's own table semantics apply. Each row's alert ID is a button:
 * that is the keyboard-reachable control that opens the alert, while a click
 * anywhere on the row does the same for mouse users.
 */
export function AlertTable({ alerts, selectedId, onSelect }) {
  return (
    <div className="table-wrap">
      <table className="alert-table">
        <caption className="sr-only">
          Security alerts. Select an alert to view its details and AI assessment.
        </caption>
        <thead>
          <tr>
            <th scope="col">Alert ID</th>
            <th scope="col">Time (UTC)</th>
            <th scope="col">Severity</th>
            <th scope="col">Host / user</th>
            <th scope="col">Category</th>
            <th scope="col">AI classification</th>
            <th scope="col">Risk</th>
            <th scope="col">Summary</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const selected = alert.alert_id === selectedId;
            return (
              <tr
                key={alert.alert_id}
                className={selected ? "is-selected" : undefined}
                aria-current={selected ? "true" : undefined}
                onClick={() => onSelect(alert.alert_id)}
              >
                <th scope="row">
                  {/*
                    aria-label rather than a visually-hidden "View alert "
                    prefix: an accessible name is built by trimming each text
                    node and joining them, so the prefix and the id ran
                    together as "View alertALRT-1003".
                  */}
                  <button
                    type="button"
                    className="button button--row"
                    aria-label={`View alert ${alert.alert_id}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      onSelect(alert.alert_id);
                    }}
                  >
                    {alert.alert_id}
                  </button>
                </th>
                <td className="cell--time">{formatTimestamp(alert.timestamp)}</td>
                <td><SeverityBadge severity={alert.severity} /></td>
                <td className="cell--host">
                  <span className="mono">{alert.hostname}</span>
                  <span className="cell--sub">{alert.username}</span>
                </td>
                <td className="cell--category">{alert.category}</td>
                <td><ClassificationBadge classification={alert.latest_classification} /></td>
                <td className="cell--risk">
                  <RiskScoreBar score={alert.latest_risk_score} compact />
                </td>
                <td className="cell--summary">{truncate(alert.description, 110)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
