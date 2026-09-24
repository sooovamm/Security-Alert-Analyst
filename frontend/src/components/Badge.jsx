/**
 * Small status chip. Colour is a secondary cue: the label always carries the
 * meaning in text, so the value is legible without relying on colour.
 */
export function SeverityBadge({ severity }) {
  return (
    <span className={`badge badge--severity-${severity}`}>
      {severity}
    </span>
  );
}

export function ClassificationBadge({ classification }) {
  if (!classification) {
    return <span className="badge badge--empty">Not analysed</span>;
  }
  return (
    <span className={`badge badge--class-${classification.toLowerCase()}`}>
      {classification}
    </span>
  );
}
