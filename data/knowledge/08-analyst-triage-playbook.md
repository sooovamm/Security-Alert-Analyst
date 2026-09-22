# Analyst Triage and Recommended-Action Playbook

This playbook maps an assessment to a *recommended* analyst action. All actions
are advisory: they are recommendations for a human analyst, never automated
destructive operations.

## Severity and verdict to action

- **Malicious / Critical or High** — Recommend immediate containment: isolate
  the host from the network, preserve volatile evidence, and escalate to
  incident response. Rotate credentials if credential access is suspected.
- **Suspicious / Medium** — Recommend investigation before action: enrich
  indicators (IP/domain reputation, file hashes), review process lineage,
  correlate with change management, and confirm with the asset owner.
- **Benign / Low** — Recommend monitor / no action, optionally tune the rule to
  reduce future noise. Document the rationale and close.

## The containment ladder (least to most disruptive)

1. **Monitor** — keep watching, no change.
2. **Investigate / enrich** — gather more evidence.
3. **Contain** — isolate host, block IP/domain, disable account.
4. **Eradicate & recover** — remove artifacts, rebuild, restore.

Prefer the least disruptive step that fits the evidence. Escalate up the ladder
as confidence in a true positive increases.

## Guardrails for automated assistance

- An AI assistant produces an *assessment and recommendation only*. It must not
  execute containment, disable accounts, or block traffic on its own.
- When retrieved knowledge does not clearly support a conclusion, the correct
  output is lower confidence and a recommendation to gather more evidence — not
  a confident guess.
- Every recommendation should be explainable with the specific evidence
  (fields in the alert and retrieved knowledge) that supports it, so a human can
  review and override it.

## Human-review reminder

Automated triage accelerates analysts; it does not replace them. High-impact
actions require human confirmation, and ambiguous or low-evidence cases should
be routed to a person rather than auto-closed.
