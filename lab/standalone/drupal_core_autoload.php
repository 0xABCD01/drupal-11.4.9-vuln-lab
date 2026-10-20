<?php
/**
 * Minimal PSR-4 autoloader so the standalone PoCs can use the real Drupal
 * core classes without a kernel, a database or a container.
 *
 * The Drupal root is taken from the DRUPAL_ROOT environment variable, or from
 * $argv[1] if the caller already resolved it.
 */
$drupalRoot = getenv('DRUPAL_ROOT') ?: NULL;
if (!$drupalRoot && isset($argv[1]) && is_dir($argv[1]) && is_file($argv[1] . '/core/lib/Drupal.php')) {
  $drupalRoot = $argv[1];
}
$drupalRoot = $drupalRoot ?: '/home/hax0r/Downloads/drupal-11.4.9';

define('LAB_DRUPAL_ROOT', rtrim($drupalRoot, '/'));

// The composer vendor tree supplies the Symfony polyfills (mb_*, etc.).
$vendor = LAB_DRUPAL_ROOT . '/vendor/autoload.php';
if (is_file($vendor)) {
  require_once $vendor;
}

spl_autoload_register(function (string $class): void {
  $root = LAB_DRUPAL_ROOT;
  $prefixes = [
    'Drupal\\Core\\' => $root . '/core/lib/Drupal/Core',
    'Drupal\\Component\\' => $root . '/core/lib/Drupal/Component',
  ];
  foreach ($prefixes as $prefix => $dir) {
    if (str_starts_with($class, $prefix)) {
      $file = $dir . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
      if (is_file($file)) {
        require $file;
      }
      return;
    }
  }
  // Module namespaces: Drupal\<module>\... -> core/modules/<module>/src/...
  if (preg_match('#^Drupal\\\\([a-z0-9_]+)\\\\#', $class, $m)) {
    $module = $m[1];
    $rel = str_replace('\\', '/', substr($class, strlen('Drupal\\' . $module . '\\')));
    foreach ([
      $root . '/core/modules/' . $module . '/src/',
      $root . '/core/modules/' . $module . '/tests/src/',
    ] as $dir) {
      $file = $dir . $rel . '.php';
      if (is_file($file)) {
        require $file;
        return;
      }
    }
  }
});
