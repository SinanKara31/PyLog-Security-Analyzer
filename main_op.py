"""
main.py
-------
CLI entry point.  Wires packages together – no business logic here.

Usage:
    python main.py --sample
    python main.py -f /var/log/nginx/access.log
    python main.py -f access.log -o report -fmt html
    python main.py -f access.log --brute-threshold 5
"""

from __future__ import annotations

__author__ = "Kara, Yusuf Sinan"

import argparse
import sys

from detection.detector import DetectorConfig, ThreatDetector
from ingestion.parser import LogParser
from ingestion.sample_data import write_sample_log
from reporting.reporter import Reporter


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_analyzer",
        description="Cybersecurity Log Analysis & Threat Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --sample\n"
            "  python main.py -f access.log\n"
            "  python main.py -f access.log -o report -fmt html\n"
            "  python main.py -f access.log --brute-threshold 5\n"
        ),
    )
    p.add_argument(
        "-f",   "--file",
        metavar="LOG_FILE",
        help="Path to the access log file."
        )
    p.add_argument(
        "-o",   "--output",
        metavar="OUTPUT_BASE",
        help="Base name for the exported report."
    )
    p.add_argument(
        "-fmt", "--format",
        choices=["json", "csv", "html"],
        default="json",
        help="Export format (default: json)."
    )
    p.add_argument(
        "--sample",
        action="store_true",
        help="Generate a built-in sample log and analyse it immediately."
    )
    p.add_argument(
        "--brute-threshold",
        type=int,
        default=10,
        metavar="N",
        help="Auth-failure count before brute-force alert (default: 10)."
        )
    return p


def main() -> None:
    """
    Orchestrate the log analysis workflow:
    CLI → parse → detect → report → export.
    """
    args = _build_parser().parse_args()

    if args.sample:
        log_path = write_sample_log()
    elif args.file:
        log_path = args.file
    else:
        _build_parser().print_help()
        print("\n[!] Provide --file <path> or use --sample.")
        sys.exit(1)

    print(f"\n[*] Analysing: {log_path}")

    try:
        entries = LogParser(log_path).parse()
    except FileNotFoundError as exc:
        print(f"[✗] {exc}")
        sys.exit(1)

    if not entries:
        print("[!] No valid log entries found.")
        sys.exit(0)

    config = DetectorConfig(brute_force_threshold=args.brute_threshold)
    threats = ThreatDetector(entries, config).analyse()

    reporter = Reporter(entries, threats)
    reporter.print_report()

    if args.output:
        reporter.export(args.output, args.format)


if __name__ == "__main__":
    main()
