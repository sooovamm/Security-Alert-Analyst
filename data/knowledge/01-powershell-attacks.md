---
title: PowerShell Security
category: PowerShell Execution
source: internal-knowledge-base
---

# PowerShell Attack Techniques and Indicators

PowerShell is a legitimate administration tool, which is exactly why attackers
abuse it (MITRE ATT&CK T1059.001). Detection depends on separating routine
scripting from adversarial use.

## High-signal indicators

- **Encoded commands.** `-EncodedCommand` / `-enc` passes a Base64 blob so the
  real command is hidden from casual inspection. Legitimate automation rarely
  needs this. Decode and inspect the payload before judging.
- **Hidden/no-profile execution.** The combination `-nop -w hidden` (NoProfile,
  hidden window) is common in malicious launchers because it suppresses UI and
  profile scripts. Benign scheduled tasks occasionally use `-NoProfile`, but a
  *hidden window on an interactive workstation* is suspicious.
- **Download cradles.** `IEX (New-Object Net.WebClient).DownloadString(...)`,
  `Invoke-WebRequest | IEX`, or `Invoke-Expression` on remote content executes
  code fetched from the network in memory, leaving little on disk. Remote hosts
  that are raw IPs, non-TLS (`http://`), or newly seen raise the score.
- **AMSI bypass.** References to `System.Management.Automation.AmsiUtils`,
  `amsiInitFailed`, or in-memory patching aim to disable the Antimalware Scan
  Interface so later stages are not scanned.
- **Execution policy bypass.** `-ExecutionPolicy Bypass` alone is weak signal —
  admins use it constantly. Weight it only alongside other indicators.

## Context that lowers suspicion

Signed internal scripts run from a controlled path (e.g. `C:\Scripts\`), during
business hours, by an expected user or service account, matching a known
scheduled task, are usually benign even with `-ExecutionPolicy Bypass`.

## Recommended analyst actions

Triage by capturing the full command line and parent process, decoding any
encoded payload, and checking the destination reputation. For confirmed
download cradles or AMSI tampering, isolate the host and hunt for follow-on
execution. Do not treat `-ExecutionPolicy Bypass` on its own as malicious.
