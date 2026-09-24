---
title: Privilege Escalation
category: Privilege Escalation
source: internal-knowledge-base
---

# Privilege-Escalation Techniques

Privilege escalation (MITRE ATT&CK TA0004) is how an attacker moves from an
initial foothold to administrative control. Because admins perform many of the
same actions legitimately, *authorisation and context* are decisive.

## Common techniques and indicators

- **Group membership changes.** `net localgroup administrators <user> /add` or
  adding accounts to Domain Admins. Malicious when a standard user elevates
  *their own* account, when it happens off-hours, or with no change ticket.
- **UAC bypass.** Auto-elevating Windows binaries abused to spawn a high-
  integrity shell without a prompt — e.g. **fodhelper.exe** or **eventvwr.exe**
  paired with an `HKCU` registry hijack (`ms-settings` / `mscfile` shell keys).
- **New account + immediate elevation.** Creating an account and instantly
  adding it to Administrators, particularly on a domain controller at an odd
  hour, is a strong compromise signal.
- **Token manipulation / service abuse.** Creating or reconfiguring services to
  run as SYSTEM, or duplicating privileged tokens.

## Benign look-alikes

- IT granting local admin under an approved change (e.g. `CHG-####`), performed
  by an admin account during business hours.
- **Group Policy** assigning documented rights such as "Log on as a service" to
  a service account during a scheduled `gpupdate`.

The same command line can be benign or malicious; the discriminators are *who*
ran it, *whether it was authorised*, *when*, and *against which account*.

## Recommended analyst actions

Correlate the change with change-management records and the actor's role. For
unauthorised self-elevation, UAC-bypass patterns, or off-hours DC account
creation, isolate/monitor the host, revert the change, and investigate initial
access. For changes matching an approved ticket, close as benign after
verification.
