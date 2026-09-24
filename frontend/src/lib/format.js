// Presentation helpers only. Verdicts, scores and thresholds come from the
// backend; nothing here derives or infers an assessment.

export const SEVERITIES = ["low", "medium", "high", "critical"];
export const CLASSIFICATIONS = ["Benign", "Suspicious", "Malicious"];
export const CATEGORIES = [
  "PowerShell Execution",
  "Suspicious Command Execution",
  "Brute-force Authentication",
  "Malware Detection",
  "Suspicious Network Connection",
  "Privilege Escalation",
  "Normal Administrative Activity",
];

/** Compact UTC timestamp: alerts are stored and compared in UTC. */
export function formatTimestamp(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().replace("T", " ").slice(0, 16) + "Z";
}

/** Risk band label for the 0-100 score, matching the backend's scoring bands. */
export function riskBand(score) {
  if (score == null) return "—";
  if (score >= 90) return "Critical";
  if (score >= 70) return "High";
  if (score >= 40) return "Moderate";
  if (score >= 20) return "Low";
  return "Minimal";
}

export function riskLevel(score) {
  if (score == null) return "none";
  if (score >= 70) return "high";
  if (score >= 40) return "moderate";
  return "low";
}

export function confidenceBand(score) {
  if (score == null) return "—";
  if (score >= 75) return "High";
  if (score >= 50) return "Moderate";
  return "Low";
}

export function truncate(text, max = 160) {
  if (!text) return "";
  return text.length > max ? `${text.slice(0, max).trimEnd()}…` : text;
}
