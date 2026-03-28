"""
detector.py
---------------------
A generic threat-detection engine.  This file contains no hard-coded threat
types, severities, or field names.  All of that lives in signatures.py.

The detector's only job is:
    1. For each entry, run every ThreatSignature against it.
    2. Separately accumulate auth failures and evaluate brute-force at the end.
    3. Return the collected ThreatEvent list.

"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.models import LogEntry, ThreatEvent
from detection import signatures


@dataclass
class DetectorConfig:
    """
    Runtime configuration for ThreatDetector.

    Using a dedicated config object (rather than bare constructor arguments)
    makes it easy to add new thresholds in the future without changing call
    sites.

    Attributes:
        brute_force_threshold : Number of 401/403 responses from one IP
                                before a BRUTE_FORCE event is emitted.
    """
    brute_force_threshold: int = 10


class ThreatDetector:
    """
    Analyses a list of LogEntry objects and returns ThreatEvent objects.

    Usage::

        config  = DetectorConfig(brute_force_threshold=5)
        threats = ThreatDetector(entries, config).analyse()

    The detector is single-use: create a new instance per analysis run.
    """

    def __init__(
            self,
            entries: List[LogEntry],
            config: Optional[DetectorConfig] = None,
    ) -> None:
        self.entries = entries
        self.config = config or DetectorConfig()
        self._auth_fails: Dict[str, List[LogEntry]] = defaultdict(list)
        self._threats: List[ThreatEvent] = []

# -- Public API ----------------------------
    def analyse(self) -> List[ThreatEvent]:
        """
        Run all detection modules and return the collected ThreatEvents.

        Per-entry checks (stateless) run first; the stateful brute-force
        evaluation runs once after all entries have been processed.

        Returns:
            List[ThreatEvent]: All detected threats, in detection order.
        """
        for entry in self.entries:
            self._run_signatures(entry)
            self._check_suspicious_method(entry)
            self._collect_auth_failure(entry)

        self._evaluate_brute_force()

        print(f"Threat detection complete: Events found: {len(self._threats)}")

        return self._threats
# -- Detection logic ----------------------------

    def _run_signatures(self, entry: LogEntry) -> None:
        """
        Apply every ThreatSignature to the entry.

        This is the entire 'engine': one loop, no hard-coded types.
        New signatures in signatures.py are picked up automatically.
        """

        for sig in signatures.SIGNATURES:
            target = sig.extract(entry)
            if sig.pattern.search(target):
                self._emit(
                    threat_type=sig.threat_type,
                    severity=sig.severity,
                    score=sig.severity_score,
                    entry=entry,
                    detail=sig.description,
                    evidence=target[:200]
                )

    def _check_suspicious_method(self, entry: LogEntry) -> None:
        """
        Check if the HTTP method is one commonly used in attacks.

        This is a simple heuristic that doesn't require regexes, but it's
        still a "signature" of suspicious activity.  Keeping it here keeps
        all rule configuration in one place.
        """
        if entry.method in signatures.SUSPICIOUS_METHODS:
            self._emit(
                threat_type="SUSPICIOUS_METHOD",
                severity=signatures.SUSPICIOUS_METHOD_SEVERITY,
                score=signatures.SUSPICIOUS_METHOD_SCORE,
                entry=entry,
                detail=f"Suspicious HTTP method: '{entry.method}' used",
                evidence=entry.path[:200],
            )

    def _collect_auth_failure(self, entry: LogEntry) -> None:
        """Accumulate 401/403 responses per IP for brute-force analysis."""
        if entry.status_code in (401, 403):
            self._auth_fails[entry.ip].append(entry)

    def _evaluate_brute_force(self) -> None:
        """
        Emit one BRUTE_FORCE event for each IP that exceeded the threshold.

        Called once after all entries have been processed so we have the
        full picture of auth failures across the entire log window.
        """
        for ip, failed_entries in self._auth_fails.items():
            count = len(failed_entries)
            if count >= self.config.brute_force_threshold:
                self._emit(
                    threat_type="BRUTE_FORCE",
                    severity="CRITICAL",
                    score=9,
                    entry=failed_entries[-1],
                    detail=(
                        f"IP {ip} triggered {count} auth failures "
                        f"(threshold: {self.config.brute_force_threshold}). "
                        f"Possible credential stuffing / brute-force attack."
                    ),
                    evidence=f"{count} requests with 401/403 status",
                )

# -- Internal Helpers ----------------------------

    def _emit(
        self,
        threat_type: str,
        severity: str,
        score: int,
        entry: LogEntry,
        detail: str,
        evidence: str = "",
    ) -> None:
        self._threats.append(ThreatEvent(
            threat_type=threat_type,
            severity=severity,
            severity_score=score,
            source_ip=entry.ip,
            timestamp=entry.timestamp,
            detail=detail,
            evidence=evidence or entry.path[:200],
        ))
