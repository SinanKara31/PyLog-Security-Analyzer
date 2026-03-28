"""
test_reporting.py
-----------------------
Tests for the reporting/ package: reporter.py and formatters.py.

Structure:
    - TestAggregation:   Reporter._build_report()
                         computes all metrics correctly
    - TestExportJSON:    formatters.export_json()
    - TestExportCSV:     formatters.export_csv()
    - TestExportHTML:    formatters.export_html()
    - TestExportRouter:  Reporter.export() routes to the correct formatter
"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"
__credits__ = "Claude (Anthropic)"

import csv
import json
import os
import sys
import pytest
from reporting.reporter import Reporter
from tests.conftest import make_entry, make_threat

# Ensure the root directory is in the path for module discovery
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


#  -- Aggregation and analysis logic ----------------------

class TestAggregation:
    """
    Validates that the Reporter correctly aggregates raw data into
    meaningful security metrics and summaries.
    """
    def test_total_requests(self):
        """Verify the counter for the total number of processed log lines."""
        assert Reporter([make_entry()] * 7, []).report.total_requests == 7

    def test_unique_ips(self):
        """
        Ensure the reporter identifies unique source IP addresses correctly.
        This is crucial for understanding the breadth of potential attackers.
        """
        entries = [make_entry(ip="a")] * 3 + [make_entry(ip="b")] * 2
        assert Reporter(entries, []).report.unique_ips == 2

    def test_top_talker_first(self):
        """
        The 'top_talkers' list must be sorted by request count descending.
        This helps analysts quickly identify the most active IPs in the logs.
        """
        entries = [make_entry(ip="a")] * 5 + [make_entry(ip="b")] * 2
        assert Reporter(entries, []).report.top_talkers[0] == ("a", 5)

    def test_top_talkers_max_10(self):
        """
        The report should only include the top 10
        most active IPs to remain concise.
        """
        entries = [make_entry(ip=f"10.0.0.{i}") for i in range(25)]
        assert len(Reporter(entries, []).report.top_talkers) <= 10

    def test_status_summary_bucketed_correctly(self):
        """Group HTTP status codes into standard categories (2xx, 4xx, 5xx)."""
        entries = [
            make_entry(status_code=200),
            make_entry(status_code=201),
            make_entry(status_code=404),
            make_entry(status_code=500),
        ]
        s = Reporter(entries, []).report.status_summary
        assert s["2xx"] == 2 and s["4xx"] == 1 and s["5xx"] == 1

    def test_threats_sorted_critical_first(self):
        """Prioritize threats in the report based on severity levels."""
        threats = [
            make_threat(severity="LOW"),
            make_threat(severity="CRITICAL"),
            make_threat(severity="HIGH"),
        ]
        events = Reporter([make_entry()], threats).report.threat_events
        assert events[0].severity == "CRITICAL"
        assert events[-1].severity == "LOW"

    def test_threat_summary_counts_by_type(self):
        """Verify that the total count for each threat type is accurate."""
        # Split the list creation into multiple lines for readability
        threats = [
            make_threat(threat_type="SQL_INJECTION"),
            make_threat(threat_type="SQL_INJECTION"),
            make_threat(threat_type="XSS_ATTEMPT"),
        ]

        report = Reporter([make_entry()], threats).report
        summary = report.threat_summary

        assert summary["SQL_INJECTION"] == 2
        assert summary["XSS_ATTEMPT"] == 1

    def test_cumulative_ip_scores(self):
        """Calculate the total risk score per IP by summing severity scores."""
        threats = [
            make_threat(source_ip="evil", severity_score=9),
            make_threat(source_ip="evil", severity_score=9),
            make_threat(source_ip="ok",   severity_score=3),
        ]
        ips = Reporter([make_entry()], threats).report.suspicious_ips
        assert ips["evil"] == 18 and ips["ok"] == 3

    def test_suspicious_ips_sorted_descending(self):
        """
        Suspicious IPs must be ranked
        by their cumulative risk score descending.
        """
        threats = [
            make_threat(source_ip="low",  severity_score=3),
            make_threat(source_ip="high", severity_score=10),
        ]
        ips = Reporter([make_entry()], threats).report.suspicious_ips
        assert list(ips)[0] == "high"

    def test_no_threats_empty_collections(self):
        """
        Report collections should be empty, not null,
        if no threats were detected.
        """
        r = Reporter([make_entry()], []).report
        assert r.threat_summary == {}
        assert r.suspicious_ips == {}

    def test_analysis_window_start_and_end(self):
        """
        Ensure the report correctly captures
        the start and end of the log timeframe.
        This is important for contextualizing the analysis period."""
        entries = [
            make_entry(timestamp="10/Jun/2024:08:00:00 +0000"),
            make_entry(timestamp="10/Jun/2024:09:00:00 +0000"),
        ]
        r = Reporter(entries, []).report
        assert r.analysis_start == "10/Jun/2024:08:00:00 +0000"
        assert r.analysis_end == "10/Jun/2024:09:00:00 +0000"


# -- Export: JSON ----------------------------------

class TestExportJSON:
    """Tests the integrity and structure of the JSON report output."""

    def test_file_created(self, tmp_path):
        """Check if the exporter physically creates a .json file."""
        Reporter([make_entry()],
                 [make_threat()]).export(str(tmp_path / "out"), "json")
        assert (tmp_path / "out.json").exists()

    def test_meta_fields_present(self, tmp_path):
        """
        The JSON output must include a metadata object with summary stats.
        """
        Reporter([make_entry()], []).export(str(tmp_path / "out"), "json")
        data = json.loads((tmp_path / "out.json").read_text())
        assert "meta" in data
        assert data["meta"]["total_requests"] == 1

    def test_threat_type_persisted(self, tmp_path):
        """
        Ensure threat event details are correctly serialized into the JSON.
        """
        output_path = str(tmp_path / "out")
        threats = [make_threat(threat_type="RCE_PROBE")]

        # Breakdown the call to stay within line length limits
        Reporter([make_entry()], threats).export(output_path, "json")

        data = json.loads((tmp_path / "out.json").read_text())
        assert data["threat_events"][0]["threat_type"] == "RCE_PROBE"

    def test_top_talkers_present(self, tmp_path):
        """
        Verify that the top talkers list is correctly included in the JSON.
        """
        output_path = str(tmp_path / "out")
        entries = [make_entry(ip="5.5.5.5")] * 3

        # Using variables makes the actual logic much easier to read
        Reporter(entries, []).export(output_path, "json")

        data = json.loads((tmp_path / "out.json").read_text())
        assert data["top_talkers"][0]["ip"] == "5.5.5.5"


# -- Export: CSV -----------------------------------

class TestExportCSV:
    """Tests the tabular formatting and row counts of CSV exports."""

    def test_file_created(self, tmp_path):
        """Check if the exporter physically creates a .csv file."""
        Reporter([make_entry()],
                 [make_threat()]).export(str(tmp_path / "out"), "csv")
        assert (tmp_path / "out.csv").exists()

    def test_header_row_correct(self, tmp_path):
        """The first row of the CSV must contain the correct header labels."""
        Reporter([make_entry()],
                 [make_threat()]).export(str(tmp_path / "out"), "csv")
        rows = list(csv.reader
                    ((tmp_path / "out.csv").read_text().splitlines()))
        assert rows[0][0] == "threat_type"

    def test_row_count_matches_threat_count(self, tmp_path):
        """Total lines in CSV should equal the header row plus data rows."""
        output_path = str(tmp_path / "out")
        threats = [make_threat()] * 3

        # Breakdown the call to keep it readable and within line limits
        Reporter([make_entry()], threats).export(output_path, "csv")

        # Read the file and convert to a list of rows
        csv_content = (tmp_path / "out.csv").read_text().splitlines()
        rows = list(csv.reader(csv_content))

        # 1 header row + 3 data rows = 4 total
        assert len(rows) == 4


# -- Export: HTML ----------------------------------------

class TestExportHTML:
    """Tests the generation of human-readable HTML reports."""
    def test_file_created(self, tmp_path):
        """Check if the exporter physically creates an .html file."""
        Reporter([make_entry()],
                 [make_threat()]).export(str(tmp_path / "out"), "html")
        assert (tmp_path / "out.html").exists()

    def test_valid_html_document(self, tmp_path):
        """The output must be a valid HTML document starting with a DOCTYPE."""
        Reporter([make_entry()], []).export(str(tmp_path / "out"), "html")
        content = (tmp_path / "out.html").read_text()
        assert content.startswith("<!DOCTYPE html>") and "</html>" in content

    def test_threat_type_appears_in_body(self, tmp_path):
        """
        Verify that security findings are rendered within the HTML body.
        """
        output_path = str(tmp_path / "out")
        threats = [make_threat(threat_type="BRUTE_FORCE")]

        # Keep the call clean and readable
        Reporter([make_entry()], threats).export(output_path, "html")

        content = (tmp_path / "out.html").read_text()
        assert "BRUTE_FORCE" in content


# -- Export routing -------------------------------------

class TestExportRouter:
    """
    Validates that the Reporter routes export requests
    to the correct formatters.
    This ensures that the user's choice of output format is respected
    """

    @pytest.mark.parametrize("fmt,ext", [
        ("json", ".json"),
        ("csv",  ".csv"),
        ("html", ".html"),
    ])
    def test_correct_extension_per_format(self, tmp_path, fmt, ext):
        """
        Verify that the router appends
        the correct file extension based on format.
        """
        Reporter([make_entry()],
                 [make_threat()]).export(str(tmp_path / "out"), fmt)
        assert (tmp_path / f"out{ext}").exists()

    def test_unknown_format_prints_warning(self, tmp_path, capsys):
        """
        Ensure a warning is printed when an unsupported export format is used.
        """
        Reporter([make_entry()], []).export(str(tmp_path / "out"), "xml")
        assert "Unknown format" in capsys.readouterr().out

    def test_format_matching_is_case_insensitive(self, tmp_path):
        """
        The export format string
        should be case-insensitive (e.g., 'JSON' vs 'json').
        """
        Reporter([make_entry()],
                 [make_threat()]).export(str(tmp_path / "out"), "JSON")
        assert (tmp_path / "out.json").exists()
