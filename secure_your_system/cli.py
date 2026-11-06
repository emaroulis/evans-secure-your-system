"""Command-line mode: python -m secure_your_system --cli [--deep] [--days N] [--html FILE] [--json FILE]"""
from __future__ import annotations

import argparse
import sys

from . import APP_NAME, __version__, report
from .scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secure_your_system", description=APP_NAME)
    p.add_argument("--cli", action="store_true", help="run in the terminal instead of opening the window")
    p.add_argument("--deep", action="store_true", help="deep scan (whole home folder; slower)")
    p.add_argument("--days", type=int, default=7, help="suspected compromise window in days (default 7)")
    p.add_argument("--html", metavar="FILE", help="save an HTML report")
    p.add_argument("--json", metavar="FILE", help="save a JSON report")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return p


def main(args) -> int:
    def progress(msg, frac):
        sys.stderr.write(f"\r[{int(frac * 100):3d}%] {msg[:90]:<90}")
        sys.stderr.flush()

    result = run_scan(window_days=max(1, args.days), deep=args.deep, progress=progress)
    sys.stderr.write("\n\n")
    print(report.to_text(result))
    if args.html:
        report.to_html(result, args.html)
        print(f"\nHTML report saved to {args.html}")
    if args.json:
        report.to_json(result, args.json)
        print(f"JSON report saved to {args.json}")
    return 2 if result.analysis["risk_level"] >= 3 else (1 if result.analysis["risk_level"] == 2 else 0)
