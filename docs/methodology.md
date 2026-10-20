# Methodology

How the three findings in this lab were derived, and how the lab is built.

---

## 1. Finding the vulnerable code

The starting point was the upstream fix set. The Drupal core repository is
hosted on GitLab at `git.drupalcode.org` (project id `59858`), and the
GitLab API exposes a compare endpoint:

```bash
curl -s "https://git.drupalcode.org/api/v4/projects/59858/repository/compare?from=11.4.9&to=11.4.10"
```

That comparison contains exactly four commits:

```
ef786b7a  fix: SA-CORE-2026-014
e5bda07d  fix: SA-CORE-2026-015
4fec58fb  fix: SA-CORE-2026-016
ffe74afe  Drupal 11.4.10
```

and touches six files:

```
core/lib/Drupal.php
core/modules/field_ui/src/Element/FieldUiTable.php
core/modules/link/src/AttributeXss.php
core/modules/navigation/js/tooltip.js
core/modules/navigation/navigation.libraries.yml
composer/Metapackage/*/composer.json
```

Mapping each fix back to the code it patches gives the vulnerable lines.
The root cause of each was then **re-derived from the source** rather than
assumed from the diff — for example, F2's root cause ("a fork that drifted
from upstream") only becomes obvious when you compare
`AttributeXss::attributes()` against `Xss::attributes()` side by side.

## 2. Confirming reachability

Reachability was established by reading the framework, not by assuming it.

**F1** — the question was whether a POST body can set `#region_callback`.
The answer is no: `FormBuilder::doProcessForm()`
(`core/lib/Drupal/Core/Form/FormBuilder.php:1087-1135`) and
`handleInputElement()` (`:1291-1391`) only ever write request data into
`#value`. That is why the advisory says core alone is not directly
exploitable, and why the lab uses a module to supply the value.

**F2** — the question was whether the `options.attributes` map of a link
field is reachable by a non-admin. It is, through the REST/JSON:API
representation, and core's own REST test asserts the round-trip
(`core/modules/menu_link_content/tests/src/Functional/Rest/MenuLinkContentResourceTestBase.php:80-92`,
verified by `assertStoredEntityMatchesSentNormalization()` in
`core/modules/rest/tests/src/Functional/EntityResource/EntityResourceTestBase.php:935`).

**F3** — the question was where `data-drupal-tooltip` comes from in core.
Grepping the templates gives menu link titles, block labels and toolbar
messages.

## 3. Building the lab

### The Drupal project

The lab uses the **drupal/drupal layout** (`drupal/legacy-project`), which
puts `core/`, `modules/`, `sites/` and `vendor/` at the document root. That is
exactly what the `drupal:11.4.9` image expects, so no Apache reconfiguration
is needed. `lab/scripts/fetch-drupal.sh` either copies an existing 11.4.9 tree
or creates one with:

```bash
composer create-project drupal/legacy-project:11.4.9 . --no-interaction --no-progress
```

### Why the lab modules exist

None of the three bugs can be triggered with core alone. Each lab module
stands in for the "contributed module" the advisory refers to:

| Module | Stands in for | What it does |
|--------|----------------|--------------|
| `vulnlab_field_ui` | a module that alters the display form | copies request data into `#region_callback` and renders a `field_ui_table` on a public route |
| `vulnlab_link` | the common "link attributes" module | exposes the link's `options.attributes` map in the widget |
| `vulnlab_nav` | a role that can enter raw HTML | renders a tooltip trigger with request-supplied attributes |

The gadgets in `vulnlab_field_ui` are deliberately limited to
`marker` / `exec` (3 allowed commands) / `sleep`, so the published lab cannot
be used as a general-purpose web shell. The vulnerability being demonstrated
is the unvalidated dispatch in core, not the gadget.

### Two tiers of PoC

| Tier | Needs | Proves |
|------|-------|--------|
| `lab/standalone/` | a Drupal source tree | the vulnerable code executes attacker-controlled data |
| `lab/poc/` | the running stack | the same thing over HTTP, plus real-browser execution for the XSS findings |

The standalone PoCs call the **real** core classes:

* `f1_field_ui_rce.php` → `Drupal\field_ui\Element\FieldUiTable::tablePreRender()`
* `f2_attribute_xss.php` → `Drupal\link\AttributeXss::sanitizeAttributes()`
  (and `Drupal\Component\Utility\Xss::attributes()` for the upstream comparison)
* `f3_tooltip_xss.js` → the `tooltipWrapper()` implementation extracted from
  the target's `tooltip.js`

## 4. Browser proofs

The XSS findings are confirmed in a real browser, not by string matching
alone:

* **F2** — the payload is
  `hx-on-click="window.__vulnlab_xss = true; event.preventDefault();"`.
  htmx evaluates `hx-on` handlers with `event` in scope
  (`new Function('event', code)` — `core/assets/vendor/htmx/htmx.js:2904`),
  so the payload can also suppress the navigation. The PoC loads the node
  page in headless Chromium, clicks the link and checks the global flag.
  The lab module attaches `core/drupal.htmx` to the lab content type so the
  htmx runtime is present — see `docs/F2-link-htmx-xss.md` §3.1 for why
  that detail matters.
* **F3** — the payload is `<img src=x onerror="window.__vulnlab_tooltip_xss = true;">`.
  The PoC loads the page in headless Chromium; the tooltip is inserted at
  attach time, so the handler fires without any interaction.

Playwright is optional. When it (or a Chromium binary) is unavailable, the
PoCs fall back to a server-side proof — that the attribute survived
sanitisation and reached the delivered HTML — and say so explicitly rather
than claiming a browser execution that did not happen.

## 5. Other findings

The same review pass also produced the lower-severity observations listed in
the README (login timing enumeration, the blocked-account error message, the
unvalidated widget plugin ID). Each was verified by reading the source and,
for the timing one, by measuring the cost of the password-verification step.

Everything else that was checked and found to be correctly implemented is
recorded in the review so it is not re-litigated: password hashing, CSRF
token generation/comparison and rotation, form-token enforcement, session
fixation, session cookie flags, session-ID storage, REST/JSON:API CSRF
enforcement, BigPipe session lifecycle, htmx session handling, SQL
construction and LIKE escaping, mail subject encoding, file-upload
sanitisation, private-file access control, and `Url::fromUserInput()`.

## 6. Responsible use

* Everything targets a **local container** started by this repository.
* The three vulnerabilities are **publicly disclosed** with CVEs assigned; the
  lab is educational material about them.
* The lab modules keep the payload surface small on purpose. Do not widen it.
* If you want to check whether a *real* site is affected, use the passive
  checks in the docs (look for `hx-on-` attributes in rendered links, check
  whether the Field UI module is installed) — do not run the PoCs against
  systems you are not authorised to test.
