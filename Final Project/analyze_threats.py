"""
analyze_threats.py  -  CPT201 Final Project
============================================
Reads the CSV produced by threat_detector.ps1 and generates:
  - threat_report.html  : styled risk dashboard for analysts
  - threat_summary.json : machine-readable summary for SIEM ingestion

Optionally enriches the report with a live system snapshot (CPU / RAM)
if the psutil library is available.

Author : Keegan
Date   : April 2026

Usage:
  python analyze_threats.py
  python analyze_threats.py path\\to\\custom_events.csv
"""

from __future__ import annotations

import csv
import html
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# psutil is optional - graceful fallback when not installed
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

# ---------------------------------------------------------------------------
# Path defaults (relative to this script's directory)
# ---------------------------------------------------------------------------
_BASE = Path(__file__).parent
DEFAULT_CSV  = _BASE / "security_events.csv"
REPORT_HTML  = _BASE / "threat_report.html"
SUMMARY_JSON = _BASE / "threat_summary.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 5          # failures in window → HIGH
MEDIUM_THRESHOLD      = 3          # failures in window → MEDIUM
FAILURE_EVENT_IDS     = {"4625", "4771"}
LOCKOUT_EVENT_ID      = "4740"
EXPLICIT_CRED_ID      = "4648"

_RISK_COLOR: dict[str, str] = {
    "CRITICAL": "#7d0000",
    "HIGH":     "#c0392b",
    "MEDIUM":   "#e67e22",
    "LOW":      "#27ae60",
    "NONE":     "#7f8c8d",
    "PENDING":  "#95a5a6",
}

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_csv(path: Path) -> list[dict]:
    """Load event records from CSV. Exits with a user-friendly message if missing."""
    if not path.exists():
        print(f"[!] Input CSV not found: {path}")
        print("[!] Run threat_detector.ps1 first.")
        print("[!] Tip: use  .\\threat_detector.ps1 -Demo  to generate sample data.")
        sys.exit(1)

    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        records = list(reader)

    if not records:
        print(f"[!] CSV is empty: {path}")
        sys.exit(1)

    return records

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(records: list[dict]) -> dict:
    """Aggregate statistics and classify risk across all event records."""
    events_by_type: Counter = Counter()
    events_by_risk: Counter = Counter()
    failures_per_user: dict[str, int] = defaultdict(int)
    lockout_users: list[str] = []
    explicit_cred_users: list[str] = []

    for row in records:
        eid   = row.get("EventID", "").strip()
        etype = row.get("EventType", "Unknown").strip()
        risk  = row.get("Risk", "LOW").strip()
        user  = row.get("User", "N/A").strip()

        events_by_type[etype] += 1
        events_by_risk[risk]  += 1

        if eid in FAILURE_EVENT_IDS and user not in ("N/A", ""):
            failures_per_user[user] += 1

        if eid == LOCKOUT_EVENT_ID and user not in ("N/A", ""):
            lockout_users.append(user)

        if eid == EXPLICIT_CRED_ID and user not in ("N/A", ""):
            explicit_cred_users.append(user)

    # Classify per-user risk
    at_risk_users: dict[str, dict] = {}
    for user, count in failures_per_user.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            level = "HIGH"
        elif count >= MEDIUM_THRESHOLD:
            level = "MEDIUM"
        else:
            level = "LOW"
        at_risk_users[user] = {"failure_count": count, "risk": level}

    # Determine overall risk for the analysis window
    has_high   = any(v["risk"] == "HIGH" for v in at_risk_users.values())
    has_medium = any(v["risk"] == "MEDIUM" for v in at_risk_users.values())

    if has_high or lockout_users:
        overall = "HIGH"
    elif has_medium or explicit_cred_users:
        overall = "MEDIUM"
    elif len(records) > 0:
        overall = "LOW"
    else:
        overall = "NONE"

    return {
        "generated_at":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events":       len(records),
        "overall_risk":       overall,
        "events_by_type":     dict(events_by_type),
        "events_by_risk":     dict(events_by_risk),
        "at_risk_users":      at_risk_users,
        "lockout_users":      sorted(set(lockout_users)),
        "explicit_cred_users": sorted(set(explicit_cred_users)),
    }

# ---------------------------------------------------------------------------
# System snapshot via psutil
# ---------------------------------------------------------------------------

def get_system_snapshot() -> dict:
    """Return live CPU and RAM metrics from the analysis host."""
    if not _PSUTIL_AVAILABLE:
        return {"note": "psutil not installed - run: pip install psutil"}

    mem = psutil.virtual_memory()
    return {
        "cpu_percent":  f"{psutil.cpu_percent(interval=1):.1f}%",
        "ram_used_gb":  f"{mem.used / 1_073_741_824:.2f} GB",
        "ram_total_gb": f"{mem.total / 1_073_741_824:.2f} GB",
        "ram_percent":  f"{mem.percent:.1f}%",
    }

# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _risk_badge(risk: str) -> str:
    """Return an inline HTML badge for a risk level. Output is pre-escaped."""
    color = _RISK_COLOR.get(risk, "#333")
    label = html.escape(risk)
    return (
        f'<span style="background:{color};color:#fff;'
        f'padding:2px 10px;border-radius:4px;font-size:0.82em;'
        f'font-weight:bold">{label}</span>'
    )


def build_html(analysis: dict, snapshot: dict, records: list[dict]) -> str:
    """Construct the full HTML report string. All user data is HTML-escaped."""
    ts      = html.escape(analysis["generated_at"])
    overall = analysis["overall_risk"]
    total   = analysis["total_events"]
    oc      = _RISK_COLOR.get(overall, "#333")   # overall color

    # -- Event type breakdown table
    type_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
        for k, v in sorted(analysis["events_by_type"].items(), key=lambda x: -x[1])
    )

    # -- At-risk users table
    user_rows = ""
    for user, info in sorted(
        analysis["at_risk_users"].items(),
        key=lambda x: -x[1]["failure_count"]
    ):
        badge = _risk_badge(info["risk"])
        user_rows += (
            f"<tr>"
            f"<td>{html.escape(user)}</td>"
            f"<td>{info['failure_count']}</td>"
            f"<td>{badge}</td>"
            f"</tr>"
        )
    if not user_rows:
        user_rows = '<tr><td colspan="3" style="text-align:center;color:#888">No at-risk users identified</td></tr>'

    # -- Raw event log (capped at 50 rows)
    event_rows = ""
    for row in records[:50]:
        badge = _risk_badge(row.get("Risk", "LOW"))
        event_rows += (
            f"<tr>"
            f"<td>{html.escape(row.get('Timestamp', ''))}</td>"
            f"<td>{html.escape(row.get('User', ''))}</td>"
            f"<td>{html.escape(row.get('EventID', ''))}</td>"
            f"<td>{html.escape(row.get('EventType', ''))}</td>"
            f"<td>{badge}</td>"
            f"</tr>"
        )

    # -- System snapshot table
    snap_rows = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in snapshot.items()
    )

    # -- Alert banners (lockouts / explicit credentials)
    alert_html = ""
    if analysis["lockout_users"]:
        names = ", ".join(html.escape(u) for u in analysis["lockout_users"])
        alert_html += (
            f'<div class="alert high">'
            f'<strong>&#9888; Account Lockout(s) Detected:</strong> {names}'
            f'</div>'
        )
    if analysis["explicit_cred_users"]:
        names = ", ".join(html.escape(u) for u in analysis["explicit_cred_users"])
        alert_html += (
            f'<div class="alert medium">'
            f'<strong>&#9888; Explicit-Credential Logon(s):</strong> {names} '
            f'- verify these are authorized.</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Threat Detection Report - CPT201</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body   {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; }}
    header {{ background: #16213e; padding: 22px 32px; border-bottom: 4px solid {oc}; }}
    header h1  {{ font-size: 1.55em; color: #fff; }}
    .subtitle  {{ color: #90a4ae; font-size: 0.88em; margin-top: 4px; }}
    .container {{ max-width: 1100px; margin: 28px auto; padding: 0 24px; }}
    .card      {{ background: #16213e; border-radius: 8px; padding: 22px;
                  margin-bottom: 22px; border-left: 4px solid {oc}; }}
    .card h2   {{ font-size: 1em; color: #64b5f6; margin-bottom: 14px;
                  text-transform: uppercase; letter-spacing: .05em; }}
    .overall   {{ font-size: 2.2em; font-weight: 700; color: {oc}; }}
    .meta      {{ color: #90a4ae; margin-top: 6px; font-size: 0.9em; }}
    table      {{ width: 100%; border-collapse: collapse; font-size: 0.88em; }}
    th         {{ background: #0f3460; padding: 9px 14px; text-align: left;
                  color: #90caf9; font-weight: 600; }}
    td         {{ padding: 8px 14px; border-bottom: 1px solid #263160; }}
    tr:hover td {{ background: #1e2d5a; }}
    .alert     {{ padding: 12px 18px; border-radius: 6px; margin-bottom: 12px;
                  font-size: 0.92em; }}
    .alert.high   {{ background: #3d0a0a; border-left: 4px solid #c0392b; }}
    .alert.medium {{ background: #3d1f00; border-left: 4px solid #e67e22; }}
    footer     {{ text-align: center; padding: 24px; color: #455a64; font-size: 0.8em; }}
  </style>
</head>
<body>
<header>
  <h1>Automated Threat Detection Report</h1>
  <div class="subtitle">CPT201 Final Project &nbsp;|&nbsp; Generated: {ts}</div>
</header>

<div class="container">

  <div class="card">
    <h2>Overall Risk Assessment</h2>
    <div class="overall">{html.escape(overall)}</div>
    <div class="meta">Total events analysed: <strong>{total}</strong></div>
  </div>

  {alert_html}

  <div class="card">
    <h2>Event Type Breakdown</h2>
    <table>
      <tr><th>Event Type</th><th>Count</th></tr>
      {type_rows}
    </table>
  </div>

  <div class="card">
    <h2>At-Risk Accounts</h2>
    <table>
      <tr><th>Username</th><th>Failed Attempts</th><th>Risk Level</th></tr>
      {user_rows}
    </table>
  </div>

  <div class="card">
    <h2>Event Log &ndash; Most Recent 50 Records</h2>
    <table>
      <tr><th>Timestamp</th><th>User</th><th>Event ID</th><th>Type</th><th>Risk</th></tr>
      {event_rows}
    </table>
  </div>

  <div class="card">
    <h2>System Snapshot (Analysis Host)</h2>
    <table>
      <tr><th>Metric</th><th>Value</th></tr>
      {snap_rows}
    </table>
  </div>

</div>
<footer>CPT201 &ndash; Automated Cybersecurity Threat Detection &amp; Log Analysis &nbsp;|&nbsp; April 2026</footer>
</body>
</html>"""

# ---------------------------------------------------------------------------
# JSON summary
# ---------------------------------------------------------------------------

def write_json(analysis: dict, snapshot: dict, path: Path) -> None:
    payload = {**analysis, "system_snapshot": snapshot}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

def print_summary(analysis: dict) -> None:
    width = 56
    print()
    print("=" * width)
    print("  Threat Analysis Summary")
    print("=" * width)
    print(f"  Generated    : {analysis['generated_at']}")
    print(f"  Total Events : {analysis['total_events']}")
    print(f"  Overall Risk : {analysis['overall_risk']}")
    print()
    print("  Event Types:")
    for etype, count in sorted(analysis["events_by_type"].items(), key=lambda x: -x[1]):
        print(f"    {etype:<38} {count}")

    if analysis["at_risk_users"]:
        print()
        print("  At-Risk Users (by failure count):")
        for user, info in sorted(
            analysis["at_risk_users"].items(),
            key=lambda x: -x[1]["failure_count"]
        ):
            print(f"    [{info['risk']:<6}]  {user}  ({info['failure_count']} failures)")

    if analysis["lockout_users"]:
        print()
        print("  Lockout events:", ", ".join(analysis["lockout_users"]))

    if analysis["explicit_cred_users"]:
        print()
        print("  Explicit-credential logons:", ", ".join(analysis["explicit_cred_users"]))

    print()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV

    print(f"[*] Loading events from : {csv_path}")
    records  = load_csv(csv_path)
    analysis = analyze(records)
    snapshot = get_system_snapshot()

    print_summary(analysis)

    html_content = build_html(analysis, snapshot, records)
    REPORT_HTML.write_text(html_content, encoding="utf-8")
    print(f"[+] HTML report saved  -> {REPORT_HTML}")

    write_json(analysis, snapshot, SUMMARY_JSON)
    print(f"[+] JSON summary saved -> {SUMMARY_JSON}")
    print()

    # Exit codes allow CI/CD pipelines to act on detected risk
    risk = analysis["overall_risk"]
    if risk == "CRITICAL":
        sys.exit(2)
    elif risk == "HIGH":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
