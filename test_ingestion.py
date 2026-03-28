"""
test_ingestion.py
-----------------------
Tests for the ingestion/ package.
"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"
__credits__ = "Claude (Anthropic)"

import os
import sys
import pytest
from ingestion.parser import LogParser
from ingestion.sample_data import write_sample_log

# Ensure the root directory is in the path for module discovery
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# -- Helpers ------------------------------

# Standard Apache/Nginx access log format line
VALID = (
    '192.168.1.10 - - [10/Jun/2024:08:01:12 +0000] '
    '"GET /login HTTP/1.1" 200 1870 "-" "Mozilla/5.0"'
)

# Line with a '-' instead of response size (common for 201/204 status codes)
VALID_NO_SIZE = (
    '10.0.0.1 - - [10/Jun/2024:09:00:00 +0000] '
    '"POST /api HTTP/1.1" 201 - "-" "curl/7.88"'
)


def parse(line: str) -> list:
    """
    Utility helper to quickly convert
    a single log string into a LogEntry object.
    Wraps the static parse_lines method for cleaner test syntax.
    """
    entries, _ = LogParser.parse_lines([line])
    return entries


# -- Field extraction -------------------

class TestFieldExtraction:
    """
    Ensures that every component of a valid log line is correctly
    mapped to the corresponding LogEntry attribute.
    """
    def test_ip(self):
        """Verify the source IP address is correctly extracted."""
        assert parse(VALID)[0].ip == "192.168.1.10"

    def test_method_uppercased(self):
        """HTTP methods should be normalized to uppercase for consistency."""
        # Intentionally inject a lowercase method into the input
        assert parse(VALID.replace('"GET', '"get'))[0].method == "GET"

    def test_path(self):
        """
        Verify extraction of the request path (excluding query parameters).
        This is crucial for accurate threat detection based on URI patterns.
        """
        assert parse(VALID)[0].path == "/login"

    def test_status_code_is_int(self):
        """
        The HTTP status code must be an integer to allow numerical filtering.
        This is important for rules that trigger on specific status codes
        """
        e = parse(VALID)[0]
        assert e.status_code == 200
        assert isinstance(e.status_code, int)

    def test_response_size_is_int(self):
        """Response size must be converted to an integer representing bytes."""
        assert parse(VALID)[0].response_size == 1870

    def test_response_size_dash_becomes_zero(self):
        """A dash '-' in logs represents 'no data' and should map to 0."""
        assert parse(VALID_NO_SIZE)[0].response_size == 0

    def test_user_agent(self):
        """
        Verify extraction of the User-Agent string from the end of the line.
        This is important for identifying scanners and bots.
        """
        assert parse(VALID)[0].user_agent == "Mozilla/5.0"

    def test_timestamp_contains_date(self):
        """The timestamp attribute must preserve the original date format."""
        assert "10/Jun/2024" in parse(VALID)[0].timestamp

    def test_raw_line_preserved(self):
        """
        The original raw log line should be kept for debugging and reporting.
        """
        assert parse(VALID)[0].raw == VALID


# -- parse_lines() behaviour -----------------------------

class TestParseLines:
    """
    Tests the static parse_lines() method, specifically regarding
    error counting and handling of non-standard input lists.
    """

    def test_returns_tuple_of_entries_and_error_count(self):
        """Ensure the method returns the expected (list, int) structure."""
        result = LogParser.parse_lines([VALID])
        assert isinstance(result, tuple) and len(result) == 2

    def test_multiple_valid_lines(self):
        """Processing multiple correct lines should result in zero errors."""
        entries, errors = LogParser.parse_lines([VALID, VALID, VALID])
        assert len(entries) == 3 and errors == 0

    def test_empty_lines_are_skipped(self):
        """
        Blank lines within the input list should be ignored without error.
        This is common in real log files and should not cause false positives.
        """
        entries, _ = LogParser.parse_lines(["", VALID, "", VALID])
        assert len(entries) == 2

    def test_garbage_line_counted_as_error(self):
        """
        Lines that do not match the regex should increase the error count.
        """
        entries, errors = LogParser.parse_lines(["not a log line"])
        assert entries == [] and errors == 1

    def test_mixed_valid_and_invalid(self):
        """
        Validate that the parser correctly separates
        valid entries from garbage.
        """
        entries, errors = LogParser.parse_lines([VALID, "GARBAGE", VALID])
        assert len(entries) == 2 and errors == 1

    def test_empty_iterable_returns_empty(self):
        """
        Passing an empty list should return empty results without crashing.
        """
        entries, errors = LogParser.parse_lines([])
        assert entries == [] and errors == 0


# -- File-based parse() behaviour -----------------------------

class TestFileParsing:
    """
    Validates instance-level parsing involving physical file paths
    and filesystem-specific error states.
    """

    def test_file_not_found_raises(self, tmp_path):
        """An invalid file path should trigger a standard FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            LogParser(str(tmp_path / "missing.log")).parse()

    def test_parse_updates_parse_errors_attribute(self, tmp_path):
        """The instance 'parse_errors' attribute must reflect failed lines."""
        path = tmp_path / "test.log"
        path.write_text(f"{VALID}\nGARBAGE\n{VALID}\n")
        parser = LogParser(str(path))
        entries = parser.parse()
        assert len(entries) == 2
        assert parser.parse_errors == 1

    def test_empty_file_returns_empty_list(self, tmp_path):
        """An existing but empty file should simply return an empty list."""
        path = tmp_path / "empty.log"
        path.write_text("")
        assert LogParser(str(path)).parse() == []


# --sample_data functionality -----------------------------

class TestSampleData:
    """
    Ensures that the sample data generation utility (write_sample_log)
    produces reliable and parseable test files.
    """
    def test_creates_file(self, tmp_path):
        """Verify the function physically creates a file on the disk."""
        path = str(tmp_path / "sample.log")
        write_sample_log(path)
        assert os.path.exists(path)

    def test_file_is_parseable(self, tmp_path):
        """The generated sample log must be compatible with the LogParser."""
        path = str(tmp_path / "sample.log")
        write_sample_log(path)
        entries = LogParser(path).parse()
        assert len(entries) > 0

    def test_returns_path(self, tmp_path):
        """The function should return the absolute path of the created file."""
        path = str(tmp_path / "sample.log")
        assert write_sample_log(path) == path
