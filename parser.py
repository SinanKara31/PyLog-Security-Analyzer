"""
parser.py
-------------------
Converts raw Apache / Nginx Combined Log Format text into LogEntry objects.

Two entry points:
    LogParser(filepath).parse()          # reads from a file on disk
    LogParser.parse_lines(iterable)      # parses in-memory lines (no I/O)

Keeping both lets production code use parse() while tests use parse_lines(),
avoiding the need for temporary files in the test suite.
"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"

import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from core.models import LogEntry


# Combined Log Format:
# {ip} - {ident} [{timestamp}] "{method} {path} {protocol}" {status} {size}
# "{referrer}" "{user_agent}"
_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'
    r'\s+\S+'
    r'\s+\S+'
    r'\s+\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<method>\S+)'
    r'\s+(?P<path>\S+)'
    r'\s+(?P<protocol>[^"]+)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\S+)'
    r'\s+"(?P<referrer>[^"]*)"'
    r'\s+"(?P<user_agent>[^"]*)"'
)


def _parse_line(raw: str) -> Optional[LogEntry]:
    """Parses a single raw log line into a LogEntry object.

    Args:
        raw: The unformatted string from the log file.

    Returns:
        A LogEntry instance if parsing succeeds; None if the line
        is malformed or doesn't match the expected pattern.
    """
    match = _LOG_PATTERN.match(raw)
    if not match:
        return None
    g = match.groupdict()
    try:
        return LogEntry(
            ip=g["ip"],
            timestamp=g["timestamp"],
            method=g["method"].upper(),
            path=g["path"],
            protocol=g["protocol"].strip(),
            status_code=int(g["status"]),
            response_size=int(g["size"]) if g["size"] != "-" else 0,
            referrer=g["referrer"],
            user_agent=g["user_agent"],
            raw=raw,
        )
    except (ValueError, KeyError):
        return None


class LogParser:
    """
    A high-performance parser for Apache and Nginx access logs.

    Attributes:
        filepath: The Path object pointing to the log file on disk.
        parse_errors: A counter for lines that failed to parse during
                      the last execution.

    """

    def __init__(self, filepath: str) -> None:
        self.filepath = Path(filepath)
        self.parse_errors = 0

# -- Public API --------------------------

    def parse(self) -> List[LogEntry]:
        """
        Reads and parses the log file from the local file system.

        Returns:
            A list of successfully parsed LogEntry objects.

        Raises:
            FileNotFoundError: If the file at self.filepath does not exist.
            OSError: If the file can't be read due to permission/system errors.
        """
        if not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

        with self.filepath.open("r", encoding="utf-8", errors="replace") as fh:
            entries, self.parse_errors = self._process(fh)

        print(f"Parsed {len(entries)} entries",
              f"Parse errors: {self.parse_errors}")
        return entries

    @classmethod
    def parse_lines(cls, lines: Iterable[str]) -> Tuple[List[LogEntry], int]:
        """
        Parses a sequence of log lines already in memory.

        This is ideal for testing or processing data streams without
        performing disk I/O.

        Args:
            lines: An iterable collection of log strings.

        Returns:
            A tuple containing (list of LogEntry objects, error count).
        """

        return cls._process(lines)

    # -- Internal helpers ------------------

    @staticmethod
    def _process(lines: Iterable[str]) -> Tuple[List[LogEntry], int]:
        """
        Internal processing loop for log line extraction.

        This method centralizes the parsing logic to ensure consistency
        between file-based and memory-based parsing (DRY principle).

        Args:
            lines: An iterable of raw log strings.

        Returns:
            A tuple of (parsed_entries, error_total).
        """
        entries: List[LogEntry] = []
        errors = 0
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue  # Skip empty lines
            entry = _parse_line(raw)
            if entry:
                entries.append(entry)
            else:
                errors += 1

        return entries, errors
