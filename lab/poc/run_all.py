#!/usr/bin/env python3
"""
Runs every end-to-end PoC in the lab and prints a summary.

Usage:
    python3 run_all.py [--url http://localhost:8080] [--no-browser]
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import BASE_URL, bad, head, ok  # noqa: E402

MODULES = [
    ("F1  SA-CORE-2026-014  field_ui RCE", "f1_field_ui_rce"),
    ("F2  SA-CORE-2026-015  link htmx stored XSS", "f2_link_htmx_xss"),
    ("F3  SA-CORE-2026-016  navigation tooltip stored XSS", "f3_navigation_tooltip_xss"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=BASE_URL)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    results = []
    for label, module_name in MODULES:
        head(label)
        module = importlib.import_module(module_name)
        sys.argv = [module_name, "--url", args.url]
        if args.no_browser:
            sys.argv.append("--no-browser")
        try:
            code = module.main()
        except SystemExit as exc:
            code = exc.code or 0
        results.append((label, code == 0))
        print()

    head("Summary")
    for label, passed in results:
        if passed:
            ok(label)
        else:
            bad(label)
    return 0 if all(p for _, p in results) else 1


if __name__ == "__main__":
    sys.exit(main())
