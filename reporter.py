"""
reporting/reporter.py
---------------------
Aggregates LogEntry and ThreatEvent lists into an AnalysisReport, renders
a colour-coded terminal summary, and routes file exports to formatters.py.

Responsibilities:
    _build_report()  – aggregate raw data into useful metrics
    print_report()   – colour-coded terminal output
    export()         – dispatch to the right formatter function
"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"

from collections import Counter, defaultdict
from typing import Dict, List

from core.models import AnalysisReport, LogEntry, ThreatEvent
from reporting import formatters


class Reporter:
    """
    Builds, prints, and exports the final security analysis report.

    This class acts as the orchestrator for data visualization and export.
    It transforms raw lists of logs and threats
    into a structured AnalysisReport.

    Attributes:
        entries: List of parsed LogEntry objects.
        threats: List of detected ThreatEvent objects.
        report: The aggregated AnalysisReport generated during initialization.
    """

    # Constants for sorting and visual styling
    _SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    # ANSI Escape Codes for terminal colors
    _SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[92m",       # Green
    }
    _RESET = "\033[0m"
    _BOLD = "\033[1m"

    def __init__(self, entries: List[LogEntry],
                 threats: List[ThreatEvent]) -> None:
        """
        Initializes the Reporter and triggers the report building process.

        Args:
            entries: Parsed web server logs.
            threats: Identified security threats.
        """
        self.entries = entries
        self.threats = threats
        self.report: AnalysisReport = self._build_report()

# -- Public API --------------------------------------------------------------
    def print_report(self) -> None:
        """Renders a professional, colour-coded summary to the terminal.

        Uses ANSI colors to highlight threat severity and ASCII bars for
        HTTP status distribution.
        """

        r = self.report
        WIDTH = 79
        sep = "═" * WIDTH

        # -- Main Header --
        print(f"\n{self._BOLD}{sep}{self._RESET}")

        # .ljust(WIDTH) ensures the background/bolding covers the entire line
        print(f"{self._BOLD} CYBERSECURITY LOG ANALYSIS REPORT{self._RESET}"
              .ljust(WIDTH))
        print(f"{self._BOLD}{sep}{self._RESET}")

        # Display the analyzed time frame and basic volume metrics
        print(f"  Log window : {r.analysis_start}  →  {r.analysis_end}")
        print(f"  Requests   : {r.total_requests:,}")
        print(f"  Unique IPs : {r.unique_ips:,}")

        # --- Section: HTTP Status ---
        header_status = "── HTTP Status Code Distribution ".ljust(WIDTH, "─")
        print(f"\n{self._BOLD}{header_status}{self._RESET}")

        for bucket, count in r.status_summary.items():
            bar = "█" * min(count // max(r.total_requests // 40, 1), 40)
            print(f"  {bucket}  {bar} {count:,}")

        # --- Section: Top Talkers ---
        header_talkers = "── Top 10 Talkers ".ljust(WIDTH, "─")
        print(f"\n{self._BOLD}{header_talkers}{self._RESET}")
        for rank, (ip, count) in enumerate(r.top_talkers, 1):
            tag = (f"  ⚠  threat-score={r.suspicious_ips[ip]}"
                   if ip in r.suspicious_ips else "")
            print(f"  {rank:>2}. {ip:<20} {count:>6,} requests{tag}")

        # --- Section: Threat Summary ---
        header_threat_sum = "── Threat Detection Summary ".ljust(WIDTH, "─")
        print(f"\n{self._BOLD}{header_threat_sum}{self._RESET}")
        if not r.threat_summary:
            print("  ✅  No threats detected.")
        else:
            # Sort threat types alphabetically for a cleaner overview
            for ttype, count in sorted(r.threat_summary.items()):
                print(f"  {ttype:<25} {count:>4} event(s)")

        # --- Section: Threat Details ---
        header_details = "── Threat Event Details ".ljust(WIDTH, "─")
        print(f"\n{self._BOLD}{header_details}{self._RESET}")
        for idx, event in enumerate(r.threat_events, 1):
            # Fetch the ANSI color code based on severity (Critical=Red, etc.)
            color = self._SEVERITY_COLORS.get(event.severity, "")

            # Main event line with color-coded severity tag
            print(
                f"  {idx:>3}. [{color}{event.severity:<8}{self._RESET}] "
                f"score={event.severity_score}  "
                f"IP={event.source_ip:<16} "
                f"type={event.threat_type}"
            )

            # Detail provides a human-readable explanation of the rule
            print(f"       → {event.detail}")
            # Truncate evidence string to 100 characters for readability
            print(f"       ✎ {event.evidence[:100]}")

        # --- Section: Suspicious IPs ---
        header_suspicious = "── Most Suspicious IPs ".ljust(WIDTH, "─")
        print(f"\n{self._BOLD}{header_suspicious}{self._RESET}")
        # Shows the "Worst of the Worst" based on their total risk score
        for ip, score in list(r.suspicious_ips.items())[:5]:
            print(f"  {ip:<20}  cumulative score = {score}")

        # --- Footer ---
        # Closing line to wrap up the report cleanly
        print(f"\n{self._BOLD}{sep}{self._RESET}\n")

    def export(self, output_path, fmt) -> None:
        """
        Routes the analysis report to the appropriate file formatter.

        This method uses a dispatch table (dictionary) to select the correct
        export function based on the user's format choice.

        Args:
            output_path: Target file path (without the file extension).
            fmt: The desired format string (e.g., 'json', 'csv', 'html').
        """
        # DISPATCH TABLE: Maps
        # Format names to functions in the 'formatters' module.
        # This avoids long 'if-elif-else' chains and
        # Makes it easy to add new formats.

        dispatch = {
            "json": formatters.export_json,
            "csv": formatters.export_csv,
            "html": formatters.export_html,
        }

        # Normalize format input to lowercase to prevent case-sensitivity
        handler = dispatch.get(fmt.lower())
        if handler:
            # Construct the final filename and
            # Call the specific formatter function
            handler(self.report, f"{output_path}.{fmt.lower()}")
        else:
            # Error handling for unsupported formats
            print(f"[!] Unknown format '{fmt}'.")
            print(f"Supported: {','.join(dispatch)}")

# -- Aggregation Logic ------------------------------------------------------

    def _build_report(self) -> AnalysisReport:
        """
        Internal logic to condense raw log data into high-level metrics.

        Processes the internal lists of 'entries' and 'threats' to populate
        a single AnalysisReport object for printing and exporting.

        Returns:
            AnalysisReport: A fully populated data container.
        """
        r = AnalysisReport()

        # 1. VOLUME METRICS
        r.total_requests = len(self.entries)
        r.unique_ips = len({e.ip for e in self.entries})

        # 2. TIME WINDOW CALCULATION
        # Extract all timestamps to find the start and end of the log period
        ts = [e.timestamp for e in self.entries if e.timestamp]
        r.analysis_start = ts[0] if ts else "N/A"
        r.analysis_end = ts[-1] if ts else "N/A"

        # 3. TRAFFIC AGGREGATION
        # Use Counter to find the 10 IPs with the highest request counts
        r.top_talkers = Counter(e.ip for e in self.entries).most_common(10)

        # 4. HTTP STATUS DISTRIBUTION
        # Groups status codes by category (e.g., 200 and 201 both become '2xx')
        status_counts: Dict[str, int] = defaultdict(int)
        for e in self.entries:
            # Floor division // 100 turns 404 into 4, then we append 'xx'
            status_counts[f"{e.status_code // 100}xx"] += 1

        # Sort by key (1xx, 2xx, etc.)
        # Before converting back to a standard dict
        r.status_summary = dict(sorted(status_counts.items()))

        # 5. THREAT ANALYSIS
        # Sort threat events by the severity order (Critical > High > ...)
        r.threat_events = sorted(
            self.threats,
            key=lambda t: self._SEVERITY_ORDER.get(t.severity, 99),
        )
        # Count occurrences of each threat type for the summary section
        r.threat_summary = dict(Counter(t.threat_type for t in self.threats))

        # 6. RISK SCORING (SUSPICIOUS IPs)
        # Sum up the severity scores for each IP to identify
        # The most dangerous actors
        ip_scores: Dict[str, int] = defaultdict(int)
        for t in self.threats:
            ip_scores[t.source_ip] += t.severity_score

        # Select the top 10 highest-scoring IPs
        # By sorting the scores descending
        r.suspicious_ips = dict(
            sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
        )

        return r
