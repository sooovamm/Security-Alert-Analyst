import { confidenceBand, riskBand, riskLevel } from "../lib/format.js";

/**
 * Risk score as a labelled bar. The number and band are always shown as text —
 * the bar is a secondary cue, so the value survives colour-blindness, a
 * greyscale print, or a screen reader.
 */
export function RiskScoreBar({ score, compact = false }) {
  if (score == null) {
    return <span className="score score--empty">{compact ? "—" : "Not scored"}</span>;
  }
  return (
    <div className={`score ${compact ? "score--compact" : ""}`}>
      <div
        className="meter"
        role="meter"
        aria-valuenow={score}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Risk score ${score} out of 100, ${riskBand(score)}`}
      >
        <span className={`meter__fill meter__fill--${riskLevel(score)}`} style={{ width: `${score}%` }} />
      </div>
      <span className="score__value">
        <strong>{score}</strong>
        {!compact && <span className="score__band">{riskBand(score)}</span>}
      </span>
    </div>
  );
}

/**
 * Confidence in the assessment — deliberately styled differently from risk so
 * the two are not mistaken for each other. Low confidence is called out,
 * because it means the evidence was thin.
 */
export function ConfidenceIndicator({ score }) {
  if (score == null) return null;
  const band = confidenceBand(score);
  return (
    <div className="confidence">
      <div
        className="meter meter--confidence"
        role="meter"
        aria-valuenow={score}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Confidence ${score} out of 100, ${band}`}
      >
        <span className="meter__fill meter__fill--confidence" style={{ width: `${score}%` }} />
      </div>
      <span className="score__value">
        <strong>{score}</strong>
        <span className="score__band">{band} confidence</span>
      </span>
    </div>
  );
}
