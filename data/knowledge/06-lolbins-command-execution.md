# Living-off-the-Land Binaries and Suspicious Command Execution

"Living off the land" means abusing trusted, signed, pre-installed system
binaries (LOLBins) to perform malicious actions while blending in with normal
administration (MITRE ATT&CK T1218 and related). Because the binaries are
legitimate, detection focuses on *anomalous use* of them.

## Frequently abused binaries

- **certutil.exe** — designed for certificates, abused with `-urlcache` /
  `-decode` to download or decode payloads from the internet.
- **bitsadmin.exe** — background file transfer service abused to fetch payloads
  (e.g. `/transfer ... /download <url> <path>`), often to temp directories.
- **wmic.exe** — `process call create` can spawn arbitrary processes and is used
  for local and remote execution.
- **mshta.exe / regsvr32.exe / rundll32.exe** — execute scripts or DLLs,
  sometimes from remote or temp locations.

## Reconnaissance command chains

Sequences like `whoami && net user && ipconfig /all` run back-to-back — 
especially under a service or application-pool identity (e.g. `iis_apppool`) — 
are consistent with post-exploitation host discovery (MITRE T1033, T1082).

## Context that matters

- **Destination.** Downloads from raw external IPs or `http://` are riskier than
  internal/known hosts.
- **Actor.** A single `ipconfig /all` from a help-desk operator during a ticket
  is routine; the same tool inside a recon chain under a web app pool is not.
- **Target of the action.** `wmic process call create "calc.exe"` is benign in
  payload but demonstrates a technique often abused — weight the technique, not
  just the outcome.

## Recommended analyst actions

Inspect the full command line, parent process, and any network destination.
For LOLBin downloads from external hosts, treat as likely malicious: isolate,
retrieve the downloaded artifact, and analyse it. For isolated, well-explained
diagnostic commands by expected users, close as benign.
