#!/usr/bin/env python3
"""
Shared helpers for the Drupal 11.4.9 vulnerability lab PoCs.

Standard library only, so the PoCs run anywhere Python 3.8+ does.
Playwright is optional and only used for the browser-execution proofs.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

BASE_URL = os.environ.get("LAB_URL", "http://localhost:8080").rstrip("/")
ADMIN_USER = os.environ.get("LAB_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("LAB_ADMIN_PASS", "admin")
EDITOR_USER = os.environ.get("LAB_EDITOR_USER", "labeditor")
EDITOR_PASS = os.environ.get("LAB_EDITOR_PASS", "LabEditor!2026")

CHROME_CANDIDATES = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
]


# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------
def ok(msg: str) -> None:
    print(f"  \033[32m[+]\033[0m {msg}")


def bad(msg: str) -> None:
    print(f"  \033[31m[-]\033[0m {msg}")


def info(msg: str) -> None:
    print(f"  \033[36m[*]\033[0m {msg}")


def head(msg: str) -> None:
    print(f"\n\033[1;34m=== {msg} ===\033[0m")


def fail(msg: str) -> int:
    bad(msg)
    return 1


# ---------------------------------------------------------------------------
# HTML form parsing
# ---------------------------------------------------------------------------
class _FormParser(HTMLParser):
    """Extracts every <form> and its hidden inputs from a page."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current = {
                "id": a.get("id", ""),
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "inputs": {},
            }
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            name = a.get("name")
            if name and a.get("type", "text").lower() in ("hidden", "text", "password", "email"):
                self._current["inputs"][name] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None

    def best(self, *hints: str) -> "_FormParser":
        """
        Returns a parser-like view of the form that best matches the hints.

        Drupal pages carry several forms (the header search form comes first),
        so picking "the first form" grabs the wrong one.
        """
        for hint in hints:
            for form in self.forms:
                if hint in form["id"] or hint in form["action"]:
                    return _FormView(form)
        if self.forms:
            return _FormView(self.forms[0])
        return _FormView({"id": "", "action": "", "method": "get", "inputs": {}})


class _FormView:
    """A read-only view over one parsed form."""

    def __init__(self, form: dict) -> None:
        self.id = form.get("id", "")
        self.action = form.get("action", "")
        self.method = form.get("method", "get")
        self.inputs = form.get("inputs", {})


def parse_form(html: str, *hints: str) -> _FormView:
    parser = _FormParser()
    parser.feed(html)
    return parser.best(*hints)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
class Lab:
    """A tiny cookie-aware HTTP client for the lab site."""

    def __init__(self, base_url: str = BASE_URL) -> None:
        self.base = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
        )
        self.opener.addheaders = [
            ("User-Agent", "drupal-vuln-lab-poc/1.0"),
            ("Accept", "*/*"),
        ]

    def url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return f"{self.base}{path if path.startswith('/') else '/' + path}"

    def request(self, path: str, data=None, headers=None, method=None, raw=False):
        url = self.url(path)
        body = None
        hdrs = dict(self.opener.addheaders)
        if headers:
            hdrs.update(headers)
        if data is not None:
            content_type = hdrs.get("Content-Type", "")
            if isinstance(data, (dict, list)) and (
                content_type.startswith("application/json")
                or content_type.startswith("application/vnd.api+json")
            ):
                body = json.dumps(data).encode()
            else:
                body = urllib.parse.urlencode(data, doseq=True).encode()
                hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with self.opener.open(req, timeout=30) as resp:
                content = resp.read()
                return resp.status, dict(resp.headers), content.decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            content = exc.read()
            return exc.code, dict(exc.headers), content.decode("utf-8", "replace")

    def get(self, path: str, headers=None):
        return self.request(path, headers=headers)

    def post(self, path: str, data, headers=None):
        return self.request(path, data=data, headers=headers)

    def post_json(self, path: str, payload, headers=None):
        hdrs = {"Content-Type": "application/vnd.api+json"}
        if headers:
            hdrs.update(headers)
        return self.request(path, data=payload, headers=hdrs)

    def patch_json(self, path: str, payload, headers=None):
        hdrs = {"Content-Type": "application/vnd.api+json"}
        if headers:
            hdrs.update(headers)
        return self.request(path, data=payload, headers=hdrs, method="PATCH")

    # -- Drupal specifics ---------------------------------------------------
    def login(self, user: str, password: str) -> bool:
        status, _, html = self.get("/user/login")
        if status != 200:
            bad(f"GET /user/login returned {status}")
            return False
        # The Drupal header carries a search form, so pick the login form by
        # its id/action rather than taking the first form on the page.
        form = parse_form(html, "user-login-form", "/user/login")
        payload = dict(form.inputs)
        payload.update({"name": user, "pass": password, "op": "Log in", "form_id": "user_login_form"})
        status, headers, html = self.post("/user/login", payload)
        if status in (302, 303):
            return True
        # Drupal re-renders the form on failure; a successful login redirects.
        if "user/logout" in html or "Log out" in html:
            return True
        return False

    def csrf_token(self) -> str:
        status, _, body = self.get("/session/token")
        if status != 200:
            return ""
        return body.strip().strip('"')

    def jsonapi(self, path: str, payload=None, method=None):
        headers = {"Accept": "application/vnd.api+json"}
        token = self.csrf_token()
        if token:
            headers["X-CSRF-Token"] = token
        if method == "PATCH":
            return self.patch_json(path, payload, headers)
        if payload is None:
            return self.request(path, headers=headers)
        return self.post_json(path, payload, headers)


# ---------------------------------------------------------------------------
# Optional browser proof
# ---------------------------------------------------------------------------
def find_chrome() -> str | None:
    for path in CHROME_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def browser_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except Exception:
        return False
    return find_chrome() is not None


def run_browser(
    url: str,
    check_js: str,
    wait_ms: int = 2500,
    login: tuple[str, str] | None = None,
    click_selector: str | None = None,
) -> tuple[bool, str]:
    """
    Opens `url` in headless Chromium and evaluates `check_js`.

    When `login` is given, the browser logs in first, so pages that require
    a session can be exercised. When `click_selector` is given, the first
    matching element is clicked before the check runs (htmx's hx-on handlers
    are event driven, so the payload needs its event).

    Returns (fired, detail). `fired` is True when the expression evaluates
    to a truthy value, which for the XSS labs means the payload executed.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover
        return False, f"playwright not installed: {exc}"

    chrome = find_chrome()
    if chrome is None:
        return False, "no chromium/chrome binary found"

    # The base URL is scheme + host, not the path minus its last segment.
    parts = urllib.parse.urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=chrome,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        try:
            page = browser.new_page()
            console: list[str] = []
            page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
            page.on("dialog", lambda d: (console.append(f"dialog: {d.message}"), d.dismiss()))

            if login:
                user, password = login
                try:
                    page.goto(f"{base}/user/login", wait_until="domcontentloaded")
                    page.fill("input[name='name']", user)
                    page.fill("input[name='pass']", password)
                    page.click("input[type='submit'], button[type='submit']")
                    page.wait_for_load_state("domcontentloaded")
                    page.wait_for_timeout(500)
                except Exception as exc:
                    console.append(f"login failed: {exc}")

            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(wait_ms)

            if click_selector:
                try:
                    page.click(click_selector, timeout=5000)
                    page.wait_for_timeout(400)
                except Exception as exc:
                    console.append(f"click failed: {exc}")

            value = page.evaluate(check_js)
            return bool(value), f"check={value!r} console={console[:5]}"
        except Exception as exc:
            return False, f"browser error: {exc}"
        finally:
            browser.close()


def require_site(base: str = BASE_URL) -> bool:
    """Checks that the lab site is reachable."""
    import urllib.request
    try:
        with urllib.request.urlopen(base + "/", timeout=10) as resp:
            resp.read(1024)
        return True
    except Exception as exc:
        bad(f"lab site not reachable at {base}: {exc}")
        print("      start it with:  make up   (or: docker compose up -d --build)")
        return False
