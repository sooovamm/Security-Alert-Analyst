# Benign Administrative Activity Baselines

A good analyst is calibrated against what *normal* looks like. Many alerts fire
on activity that is entirely expected. Knowing the baseline prevents false
positives and reduces alert fatigue.

## Common legitimate activity that triggers alerts

- **Scheduled backups.** Backup agents (e.g. `backupagent.exe`) running full or
  incremental jobs at their configured nightly time, uploading to an approved
  vault or cloud target over TLS.
- **Patch management.** SCCM/WSUS deployments (`ccmexec.exe`) installing signed
  KB updates during the maintenance window; servers contacting Microsoft update
  CDNs.
- **Administrative remote sessions.** RDP (`mstsc.exe`) from a designated **jump
  host** to servers during business hours, by admin accounts, is the expected
  path for server management.
- **Software deployment.** `msiexec.exe /qn` silent installs of approved
  packages from the internal packaging share.
- **Directory administration.** Password resets and group changes performed
  through management consoles (`dsa.msc`) by IT for new hires or approved
  requests.

## What keeps these benign

- **Expected actor:** a known admin account or service account, not a random
  standard user.
- **Expected source:** jump hosts, management subnets, or the service host — not
  an arbitrary workstation or external IP.
- **Expected timing:** during business hours or the defined maintenance window.
- **Traceability:** correlates to a change ticket, schedule, or standard
  operating procedure.

## How to use this baseline

When an alert matches a known-good pattern on actor, source, timing, and
authorisation, it should be classified benign with high confidence and a
"monitor / no action" recommendation. Deviations from the baseline — off-hours
execution, unexpected accounts, external sources, missing change records — are
what push an otherwise routine action toward suspicious.
