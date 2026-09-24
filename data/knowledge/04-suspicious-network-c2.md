---
title: Suspicious Network Activity
category: Suspicious Network Connection
source: internal-knowledge-base
---

# Suspicious Network Connections and Command-and-Control

Not every outbound connection is malicious; servers legitimately talk to update
CDNs and cloud services constantly. The task is to separate normal egress from
command-and-control (MITRE T1071) and data exfiltration (T1041).

## Command-and-control indicators

- **Beaconing.** Regular, low-jitter callbacks (e.g. every 60s +/- a few
  seconds) with uniform small payloads are a hallmark of C2 check-ins. Human and
  application traffic is bursty and irregular; beacons are metronomic.
- **Reputation.** Connections to IPs on threat-intel blocklists, freshly
  registered domains, or bulletproof-hosting ranges materially raise the score.
- **Anonymity networks.** Connections to published **Tor** nodes (ORPorts such
  as 9001/9030) or commercial VPN exit ranges from hosts with no business need
  are suspicious.
- **Unusual ports/protocols.** Non-standard ports for the process, DNS
  tunnelling (large volumes of TXT queries), or protocol/port mismatches.

## Data-exfiltration indicators

Large outbound transfers to an unfamiliar external host — especially from a
sensitive system like a database server, outside maintenance windows — suggest
exfiltration. Compare volume and destination against the host's normal baseline.

## Benign look-alikes

- **Windows Update / Microsoft CDNs** (e.g. `13.107.x.x`) during patch windows.
- **Approved cloud backup or SaaS endpoints** on schedule from the expected
  service account.
- Software update checks from browsers and agents.

The differentiator is *destination reputation + timing + baseline*, not the mere
existence of outbound TLS.

## Recommended analyst actions

Enrich the destination with threat intel and passive DNS. For confirmed C2 or
exfil, isolate the host, block the destination at the perimeter, and preserve
netflow. For recognised CDN/backup traffic on schedule, close as benign.
