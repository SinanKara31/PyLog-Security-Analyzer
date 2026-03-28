"""
models.py
--------------
Shared data structures used by every package in this project.
No business logic lives here only plain dataclasses.

These are the only types that cross package boundaries.
Package-internal types (e.g. ThreatSignature) live in their own package.
"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class LogEntry:
    """One fully-parsed line from an Apache or Nginx Combined Log Format file.

    All string fields are stripped and normalized by the LogParser before
    instantiation. For example, the method is always uppercased, and the
    referrer is set to '-' when absent.

    Attributes:
        ip: The IPv4 or IPv6 address of the client.
        timestamp: The datetime string from the log.
        method: The HTTP method (e.g., 'GET', 'POST').
        path: The requested URI path.
        protocol: The HTTP protocol version (e.g., 'HTTP/1.1').
        status_code: The HTTP response status code (e.g., 200, 404).
        response_size: The size of the response in bytes (0 if logged as '-').
        referrer: The HTTP referrer URL.
        user_agent: The client's User-Agent string.
        raw: The original, unparsed log line (useful for debugging).
    """
    ip: str
    timestamp: str
    method: str
    path: str
    protocol: str
    status_code: int
    response_size: int
    referrer: str
    user_agent: str
    raw: str


@dataclass
class ThreatEvent:
    """
    One detected threat with sufficient context for a human analyst.

    Attributes:
        threat_type: The category of the threat (e.g. 'SQL_INJECTION').
        severity: A human-readable label ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        severity_score: An integer from 1-10
                        used for sorting and cumulative scoring.
        source_ip: The IP address originating the threat.
        timestamp: The time the threat was detected.
        detail: A descriptive summary of what happened.
        evidence: The specific string fragment or payload
                  that triggered the match.
    """
    threat_type: str
    severity: str
    severity_score: int
    source_ip: str
    timestamp: str
    detail: str
    evidence: str


@dataclass
class AnalysisReport:
    """
    Aggregated results produced by the Reporter module.

    All fields have safe default values so callers can build a report
    incrementally without encountering KeyErrors or uninitialized variables.

    Attributes:
        total_requests: The total number of log lines processed.
        unique_ips: The count of distinct IP addresses found.
        analysis_start: The earliest timestamp in the parsed logs.
        analysis_end: The latest timestamp in the parsed logs.
        top_talkers: A list of tuples containing (IP, request_count).
        status_summary: A dictionary mapping status codes to their frequency.
        threat_events: A list of all detected ThreatEvent instances.
        threat_summary: A dictionary mapping threat types
                        to their occurrence count.
        suspicious_ips: A dictionary mapping IPs
                        to their total cumulative threat score.
    """
    total_requests: int = 0
    unique_ips: int = 0
    analysis_start: str = ""
    analysis_end: str = ""
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)
    status_summary: Dict[str, int] = field(default_factory=dict)
    threat_events: List[ThreatEvent] = field(default_factory=list)
    threat_summary: Dict[str, int] = field(default_factory=dict)
    suspicious_ips: Dict[str, int] = field(default_factory=dict)
