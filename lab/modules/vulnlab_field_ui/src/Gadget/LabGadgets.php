<?php

declare(strict_types=1);

namespace Drupal\vulnlab_field_ui\Gadget;

/**
 * A tiny registry of lab gadgets.
 *
 * The point of the lab is to prove ONE thing: that Drupal core executes a
 * callable that was supplied from OUTSIDE the core code (i.e. from the
 * request), with no validation whatsoever.
 *
 * To keep the lab safe to publish and to run, the callable is chosen from a
 * fixed registry of deliberately harmless gadgets instead of being an
 * arbitrary PHP callable. A real exploit would pass any callable it liked.
 *
 * Note the calling convention: core invokes the callable with EXACTLY ONE
 * argument, the row array, by reference:
 *
 *     call_user_func_array($row['#region_callback'], [&$row]);
 *
 * so a gadget receives the row and reads whatever else it needs from it.
 * That is faithful to the real threat model: the attacker controls both
 * WHICH callable runs and the data that is handed to it.
 *
 * The gadgets are intentionally boring but unmistakable:
 *   - 'marker'  writes a marker file and reports success, so the page
 *               visibly proves that the chosen code ran.
 *   - 'exec'    runs ONE command from a small allow-list (id / whoami /
 *               uname -a) and returns its output, to show the impact class
 *               (arbitrary command execution) without shipping a shell.
 *   - 'sleep'   sleeps, to show that the sink is reachable from a plain GET.
 */
final class LabGadgets {

  /**
   * The allow-list of gadget names.
   */
  public const GADGETS = ['marker', 'exec', 'sleep'];

  /**
   * Commands the 'exec' gadget is allowed to run.
   */
  public const ALLOWED_COMMANDS = ['id', 'whoami', 'uname -a'];

  /**
   * The row key that carries the request-supplied gadget argument.
   */
  public const ARG_KEY = 'lab_arg';

  /**
   * The request-supplied gadget argument.
   *
   * Core invokes the callable with EXACTLY ONE argument (the row), so the
   * gadget argument is handed over separately. The row itself remains
   * attacker-influenced - that is the data core passes to the callable.
   *
   * @var string
   */
  protected static string $argument = '';

  /**
   * Sets the argument the next gadget invocation will read.
   */
  public static function setArgument(string $argument): void {
    self::$argument = $argument;
  }

  /**
   * Resolves a gadget name to the callable that core will execute.
   *
   * @param string $name
   *   The gadget name taken from the request.
   *
   * @return array|null
   *   A [class, method] pair, or NULL when the gadget is unknown.
   */
  public static function resolve(string $name): ?array {
    if (!in_array($name, self::GADGETS, TRUE)) {
      return NULL;
    }
    return [self::class, $name];
  }

  /**
   * Reads the request-supplied argument out of the row core handed us.
   *
   * @param array $row
   *   The row array.
   *
   * @return string
   *   The argument, or an empty string.
   */
  public static function argument(array $row): string {
    if (self::$argument !== '') {
      return self::$argument;
    }
    return isset($row[self::ARG_KEY]) && is_scalar($row[self::ARG_KEY])
      ? (string) $row[self::ARG_KEY]
      : '';
  }

  /**
   * Returns a writable directory for marker files.
   */
  public static function markerDirectory(): string {
    $dir = NULL;
    try {
      $dir = \Drupal::service('file_system')->getDirectory('private://') . '/vulnlab';
    }
    catch (\Throwable) {
      $dir = NULL;
    }
    if ($dir === NULL || !is_dir($dir) && !@mkdir($dir, 0770, TRUE) && !is_dir($dir)) {
      $dir = sys_get_temp_dir() . '/vulnlab';
    }
    if (!is_dir($dir)) {
      @mkdir($dir, 0770, TRUE);
    }
    return $dir;
  }

  /**
   * Gadget: write a marker file and report success.
   *
   * @param array $row
   *   The field_ui_table row, passed by reference by core.
   *
   * @return string
   *   The region the row belongs to.
   */
  public static function marker(array &$row): string {
    $dir = self::markerDirectory();
    $payload = [
      'gadget' => 'marker',
      'arg' => self::argument($row),
      'row_keys' => array_keys($row),
      'row_region' => $row['region']['#value'] ?? NULL,
      'php' => PHP_VERSION,
      'uid' => \Drupal::currentUser()->id(),
      'unauthenticated' => \Drupal::currentUser()->isAnonymous(),
      'time' => date('c'),
    ];
    @file_put_contents(
      $dir . '/marker-' . substr(hash('sha256', uniqid('', TRUE)), 0, 12) . '.json',
      json_encode($payload, JSON_PRETTY_PRINT)
    );
    \Drupal::logger('vulnlab_field_ui')->notice('SA-CORE-2026-014 gadget "marker" executed. @arg', [
      '@arg' => self::argument($row),
    ]);
    return 'content';
  }

  /**
   * Gadget: run one allow-listed command and report its output.
   *
   * @param array $row
   *   The field_ui_table row, passed by reference by core.
   *
   * @return string
   *   The region the row belongs to.
   */
  public static function exec(array &$row): string {
    $requested = trim(self::argument($row));
    $command = in_array($requested, self::ALLOWED_COMMANDS, TRUE) ? $requested : 'id';
    $output = [];
    @exec($command . ' 2>&1', $output);
    $result = implode("\n", $output);
    \Drupal::logger('vulnlab_field_ui')->notice('SA-CORE-2026-014 gadget "exec" ran @cmd: @out', [
      '@cmd' => $command,
      '@out' => $result,
    ]);
    $row['human_name'] = [
      '#markup' => '<span class="vulnlab-exec-output">' . htmlspecialchars($result, ENT_QUOTES) . '</span>',
    ];
    return 'content';
  }

  /**
   * Gadget: sleep, to show that the sink is reachable without side effects.
   *
   * @param array $row
   *   The field_ui_table row, passed by reference by core.
   *
   * @return string
   *   The region the row belongs to.
   */
  public static function sleep(array &$row): string {
    $seconds = max(0, min(10, (int) self::argument($row)));
    sleep($seconds);
    \Drupal::logger('vulnlab_field_ui')->notice('SA-CORE-2026-014 gadget "sleep" slept @s s', ['@s' => $seconds]);
    return 'content';
  }

}
