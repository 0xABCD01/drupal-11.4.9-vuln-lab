<?php

declare(strict_types=1);

namespace Drupal\vulnlab_field_ui\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\vulnlab_field_ui\Gadget\LabGadgets;
use Symfony\Component\HttpFoundation\Request;

/**
 * Serves an UNAUTHENTICATED field_ui_table whose #region_callback is chosen
 * by the request.
 *
 * This controller plays the role that a contributed module plays in the
 * advisory: it is the code that copies REQUEST data into the render array.
 * Drupal core then executes whatever callable ended up in '#region_callback'
 * (core/modules/field_ui/src/Element/FieldUiTable.php:72):
 *
 *     $region_name = call_user_func_array($row['#region_callback'], [&$row]);
 *
 * The lab keeps the callable inside a fixed gadget registry so the published
 * lab cannot be used as a general purpose web shell. The vulnerability being
 * demonstrated is the unvalidated dispatch in core, not the gadget itself.
 */
class PublicRceController extends ControllerBase {

  /**
   * Renders the field_ui_table.
   */
  public function render(Request $request): array {
    $gadget = (string) ($request->query->get('gadget') ?? 'marker');
    $arg = (string) ($request->query->get('arg') ?? 'vulnlab');

    $callable = LabGadgets::resolve($gadget);
    if ($callable === NULL) {
      return [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => sprintf('Unknown gadget "%s". Known gadgets: %s', $gadget, implode(', ', LabGadgets::GADGETS)),
      ];
    }

    // The gadget argument travels separately, because core invokes the
    // callable with exactly one argument (the row).
    LabGadgets::setArgument($arg);

    // The render array that core will pre-render. '#region_callback' is the
    // attacker-influenced value; core invokes it with call_user_func_array().
    $elements = [
      '#type' => 'field_ui_table',
      '#attached' => ['library' => ['field_ui/drupal.field_ui']],
      '#regions' => [
        'content' => ['title' => $this->t('Content'), 'invisible' => TRUE],
        'hidden' => ['title' => $this->t('Disabled')],
      ],
      'lab_field' => [
        '#row_type' => 'field',
        // <<< The value that Drupal core executes without validating it. >>>
        '#region_callback' => $callable,
        '#js_settings' => ['rowHandler' => 'field'],
        'human_name' => ['#plain_text' => 'Lab field'],
        'machine_name' => ['#markup' => 'lab_field'],
        'weight' => ['#type' => 'textfield', '#value' => 0, '#title' => 'Weight', '#title_display' => 'invisible'],
        'region' => [
          '#type' => 'select',
          '#title' => 'Region',
          '#title_display' => 'invisible',
          '#options' => ['content' => 'Content', 'hidden' => 'Disabled'],
          '#value' => 'content',
        ],
        'parent_wrapper' => [
          'parent' => [
            '#type' => 'select',
            '#title' => 'Parent',
            '#title_display' => 'invisible',
            '#options' => ['content' => 'Content', 'hidden' => 'Disabled'],
            '#value' => '',
          ],
          'hidden_name' => ['#type' => 'hidden', '#value' => 'lab_field'],
        ],
      ],
    ];

    return [
      '#type' => 'container',
      '#cache' => ['max-age' => 0],
      '#attributes' => ['class' => ['vulnlab-rce']],
      'intro' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('SA-CORE-2026-014 lab: the gadget "@gadget" is executed by Drupal core during pre-render of the field_ui_table below.', [
          '@gadget' => $gadget,
        ]),
      ],
      'table' => $elements,
      'outbound' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('Requested gadget argument: @arg', ['@arg' => $arg]),
      ],
    ];
  }

}
