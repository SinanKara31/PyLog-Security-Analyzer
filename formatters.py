"""
formatters.py
-----------------------
Serializes an AnalysisReport into persistent file formats (JSON, CSV, HTML).

Architecture Note:
    - reporter.py: Logic layer (WHAT is reported).
    - formatters.py: Presentation/Persistence layer (HOW it is saved).

This separation ensures that adding a new output format does not require
modifying the core analysis logic.
"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"
__credits__ = "Claude (Anthropic)"

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone

from core.models import AnalysisReport


def export_json(report: AnalysisReport, path: str) -> None:
    """
    Serializes the report into a structured JSON format.

    Designed for high interoperability, making it suitable for SIEM (Security
    Information and Event Management)
    ingestion or automated downstream scripts.
    """
    # Create a comprehensive dictionary
    # Containing metadata and aggregated results
    payload = {
        "meta": {
            "total_requests": report.total_requests,
            "unique_ips":     report.unique_ips,
            "window_start":   report.analysis_start,
            "window_end":     report.analysis_end,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
        },
        "status_summary": report.status_summary,
        "top_talkers":    [{"ip": ip, "requests": c} for ip,
                           c in report.top_talkers],
        "threat_summary": report.threat_summary,
        "suspicious_ips": report.suspicious_ips,
        # Convert dataclass objects to dictionaries for JSON serialization
        "threat_events":  [asdict(t) for t in report.threat_events],
    }

    # Save with 2-space indentation for human readability and machine parsing
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"[✓] JSON report saved → {path}")


def export_csv(report: AnalysisReport, path: str) -> None:
    """
    Exports threat event details to a flat CSV file.

    Optimized for spreadsheet applications like Microsoft Excel
    or Google Sheets,
    allowing security analysts to perform manual filtering and sorting.
    """
    # Define the column headers explicitly to ensure consistent data structure
    fieldnames = [
        "threat_type", "severity", "severity_score",
        "source_ip", "timestamp", "detail", "evidence",
    ]

    # newline="" is used to prevent extra blank lines on Windows platforms
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        # Iterate through all detected threats and write them as rows
        for event in report.threat_events:
            # asdict() ensures the ThreatEvent dataclass matches the fieldnames
            writer.writerow(asdict(event))
    print(f"[✓] CSV report saved  → {path}")


def export_html(report: AnalysisReport, path: str) -> None:
    """
    Generates a standalone HTML5 dashboard with a modern Dark Mode UI.

    This report is fully self-contained (no external CSS/JS) and can be viewed
    locally in any browser, making it ideal for sharing via email or Slack.
    """
    # Severity-to-Hex mapping for dynamic UI highlighting
    _COLOR = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#3498db",
        "LOW":      "#95a5a6",
    }

    # Build the table rows dynamically
    # Using list comprehension and string joining
    rows = "".join(
        f"<tr>"
        f"<td style='color:{_COLOR.get(e.severity, '#ccc')};font-weight:bold'>"
        f"{e.severity}</td>"
        f"<td>{e.severity_score}</td>"
        f"<td>{e.source_ip}</td>"
        f"<td>{e.threat_type}</td>"
        f"<td>{e.timestamp}</td>"
        f"<td>{e.detail[:80]}</td>"
        f"</tr>\n"
        for e in report.threat_events
    )

    # Basic HTML template with inline CSS for styling
    html = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<title>Security Log Report</title><style>"
        "body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}"
        "h1{color:#58a6ff}h2{color:#8b949e;border-bottom:1px solid #30363d}"
        "table{width:100%;border-collapse:collapse;margin-top:1rem}"
        "th{background:#161b22;color:#58a6ff;padding:.5rem;text-align:left}"
        "td{padding:.4rem .6rem;border-bottom:1px solid #21262d}"
        "tr:hover{background:#161b22}"
        ".stat{display:inline-block;margin:.5rem 1rem;background:#161b22;"
        "padding:.8rem 1.5rem;border-radius:6px;border:1px solid #30363d}"
        "</style></head><body>"
        "<h1>🔐 Cybersecurity Log Analysis Report</h1>"
        "<div>"
        f"<span class='stat'>📦 Requests: <strong>{report.total_requests:,}</strong></span>"
        f"<span class='stat'>🌐 Unique IPs: <strong>{report.unique_ips:,}</strong></span>"
        f"<span class='stat'>🚨 Threats: <strong>{len(report.threat_events)}</strong></span>"
        "</div>"
        "<h2>Threat Events</h2>"
        "<table><tr>"
        "<th>Severity</th><th>Score</th><th>Source IP</th>"
        "<th>Type</th><th>Timestamp</th><th>Detail</th>"
        f"</tr>{rows}</table>"
        "</body></html>"
    )

    # Write the complete HTML buffer to the specified file path
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"[✓] HTML report saved → {path}")
