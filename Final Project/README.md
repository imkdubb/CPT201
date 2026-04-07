# Automated Brute-Force Threat Detection & Log Analysis

**CPT201 Final Project | Contributers: Keegan Windley, Delaura Ohave | April 2026**

---

## Overview

A two-stage cybersecurity automation pipeline that monitors Windows Security event logs for credential-based attack patterns, classifies accounts by risk level, and delivers analyst-ready reports without manual log review.

| Stage | Script                | Language   | Purpose                                    |
| ----- | --------------------- | ---------- | ------------------------------------------ |
| 1     | `threat_detector.ps1` | PowerShell | Collect & risk-score authentication events |
| 2     | `analyze_threats.py`  | Python     | Aggregate, report, and export findings     |

---

## Monitored Event IDs

| Event ID | Description                     | Risk Implication                         |
| -------- | ------------------------------- | ---------------------------------------- |
| 4625     | Failed logon                    | Brute-force / credential spray indicator |
| 4648     | Logon with explicit credentials | Pass-the-hash / stolen credential reuse  |
| 4771     | Kerberos pre-auth failure       | Kerberos brute-force indicator           |
| 4776     | NTLM credential validation      | Off-domain authentication attempt        |
| 4740     | Account lockout                 | Confirms active attack sequence          |

---

## Project Files

```
Final Project/
├── threat_detector.ps1   # Stage 1 – PowerShell collection & risk scoring
├── analyze_threats.py    # Stage 2 – Python analysis & report generation
├── pseudocode.txt        # Workflow pseudocode & data flow documentation
├── report.txt
└── README.md
```

Generated at runtime:

```
├── security_events.csv   # Output of Stage 1; input to Stage 2
├── threat_report.html    # Analyst-facing HTML dashboard
└── threat_summary.json   # Machine-readable SIEM-ingestible summary
```

---

## Requirements

### PowerShell (Stage 1)

- PowerShell 5.1 or later (included with Windows 10/11)
- `Event Log Readers` group membership **or** Local Administrator rights to read the Security log
- WinRM enabled on target if using `-RemoteComputer` (remote query mode)

### Python (Stage 2)

- Python 3.9+
- `psutil` library (optional – enables CPU/RAM snapshot in report)

```powershell
pip install psutil
```

---

## Quick Start

### Option A – Demo mode (no admin rights required)

```powershell
# Stage 1: generate synthetic events
.\threat_detector.ps1 -Demo

# Stage 2: analyze and produce reports
python analyze_threats.py
```

Then open **threat_report.html** in any browser.

---

### Option B – Real event log (local machine)

```powershell
# Run as Administrator or as a member of Event Log Readers
.\threat_detector.ps1 -DaysBack 7

python analyze_threats.py
```

---

### Option C – Remote machine

```powershell
# WinRM must be enabled on the target
.\threat_detector.ps1 -RemoteComputer DC01 -DaysBack 3

python analyze_threats.py
```

---

## Parameters – threat_detector.ps1

| Parameter              | Default                 | Description                   |
| ---------------------- | ----------------------- | ----------------------------- |
| `-RemoteComputer`      | local machine           | Target hostname or IP         |
| `-OutputPath`          | `.\security_events.csv` | CSV output location           |
| `-DaysBack`            | `7`                     | Look-back window (days)       |
| `-MaxEvents`           | `2000`                  | Maximum events to retrieve    |
| `-BruteForceThreshold` | `5`                     | Failures to trigger HIGH risk |
| `-Demo`                | off                     | Inject synthetic events       |

---

## Risk Classification Logic

| Condition                                        | Risk Level |
| ------------------------------------------------ | ---------- |
| User has ≥ 5 failed logons (4625/4771) in window | HIGH       |
| User has 3–4 failed logons in window             | MEDIUM     |
| User has 1–2 failed logons in window             | LOW        |
| Any account lockout (4740)                       | HIGH       |
| Any explicit-credential logon (4648)             | MEDIUM     |

**Overall risk** is the highest risk level across any account in the window.

---

## Exit Codes (analyze_threats.py)

| Code | Meaning                | CI/CD Action            |
| ---- | ---------------------- | ----------------------- |
| `0`  | LOW or NONE risk       | Pass                    |
| `1`  | HIGH risk detected     | Warning / alert analyst |
| `2`  | CRITICAL risk detected | Block / page on-call    |

---

## Compliance Notes

| Framework           | Relevant Controls                                                  |
| ------------------- | ------------------------------------------------------------------ |
| NIST SP 800-53      | AU-2 (Audit Events), AU-6 (Audit Review), SI-4 (System Monitoring) |
| GDPR                | Article 5 (Data minimization), Article 32 (Security of processing) |
| HIPAA Security Rule | §164.312 Audit Controls, Access Control                            |

- All HTML output is passed through `html.escape()` — prevents XSS (OWASP A03).
- No credentials are stored or transmitted by either script.
- Deploy only with documented organizational authorization.

---

## Testing Summary

| Test             | Method                         | Result                                                      |
| ---------------- | ------------------------------ | ----------------------------------------------------------- |
| Demo mode        | `-Demo` flag                   | All 12 synthetic events parsed; HIGH risk correctly flagged |
| Zero results     | Local machine with no failures | Graceful exit with informational message                    |
| Remoting failure | Unreachable hostname           | Fallback to local log; no crash                             |
| Missing CSV      | Delete CSV before Python run   | Clear setup instructions; exit code 1                       |
| Missing psutil   | Uninstall psutil               | Graceful note in report; no crash                           |
