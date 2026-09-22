# Brute-force and Credential-Access Patterns

Authentication attacks (MITRE ATT&CK T1110) span brute forcing, password
spraying, and credential stuffing. The distinguishing feature is the *shape* of
the failure pattern, not any single failed logon.

## Distinguishing the patterns

- **Brute force (vertical).** Many password attempts against *one* account in a
  short window. On Windows this appears as bursts of Event ID 4625 for a single
  username; on Linux as repeated `sshd` "failed password" lines for one user.
  A high rate (tens to hundreds per minute) from a single source is strong
  signal, especially against `root`, `administrator`, or exposed RDP/SSH.
- **Password spray (horizontal).** *One or few* attempts against *many*
  accounts, deliberately staying under lockout thresholds. Look for a single
  source host generating one failed logon each across dozens of distinct
  accounts within minutes.
- **Credential stuffing.** Reused breached credentials, often distributed across
  many source IPs, with an unusually high success ratio.

## Benign look-alikes

- A user mistyping a password: a small number of 4625 events (typically < 5)
  immediately followed by a 4624 success for the same account at a plausible
  time.
- **Account lockout (4740)** for a service account after a password rotation
  that was not propagated to the job scheduler — repeated failures from the
  same host, but tied to a known change.

## What raises the score

External source IP, internet-exposed service (RDP/SSH), privileged target
account, off-hours timing, and — most importantly — a *successful* logon after
a failure burst, which may indicate compromise rather than a mistyped password.

## Recommended analyst actions

Confirm whether any attempt succeeded. For active brute force from an external
IP, block the source and consider rate-limiting or MFA enforcement. For spray
patterns, review all targeted accounts for a success and reset if needed. A few
failures followed by a legitimate success is normally benign.
