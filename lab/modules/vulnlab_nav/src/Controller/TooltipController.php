<?php

declare(strict_types=1);

namespace Drupal\vulnlab_nav\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Renders a tooltip trigger whose attributes come from the request.
 *
 * The Navigation module's tooltip behaviour (core/modules/navigation/js/
 * tooltip.js) attaches to ANY element carrying a data-drupal-tooltip
 * attribute. Its wrapper is built by string interpolation and handed to
 * insertAdjacentHTML(), so the attribute value is parsed as MARKUP.
 *
 * Core itself feeds that attribute from menu link titles, block labels and
 * toolbar messages. This controller provides the same sink with a value taken
 * straight from the request, which is the "role with permission to enter HTML
 * tags containing specific data attributes" scenario from the advisory.
 */
class TooltipController extends ControllerBase {

  /**
   * Renders the tooltip trigger.
   */
  public function render(Request $request) {
    $text = (string) ($request->query->get('tooltip') ?? '<img src=x onerror="window.__vulnlab_tooltip_xss=true">');
    $class = (string) ($request->query->get('class') ?? 'admin-toolbar__tooltip');

    $build = [
      '#type' => 'container',
      // The lab page must never be served from the render cache, otherwise
      // a stale payload would be shown.
      '#cache' => ['max-age' => 0],
      '#attributes' => ['class' => ['vulnlab-tooltip']],
      '#attached' => ['library' => ['navigation/internal.tooltip']],
      'intro' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('SA-CORE-2026-016 lab: the tooltip text below is copied into data-drupal-tooltip and then re-parsed as HTML by core/modules/navigation/js/tooltip.js.'),
      ],
      'trigger' => [
        '#type' => 'html_tag',
        '#tag' => 'a',
        '#value' => 'Hover me',
        '#attributes' => [
          'href' => '#',
          'data-drupal-tooltip' => $text,
          'data-drupal-tooltip-class' => $class,
          'class' => ['vulnlab-tooltip-trigger'],
        ],
      ],
    ];

    return $build;
  }

}
