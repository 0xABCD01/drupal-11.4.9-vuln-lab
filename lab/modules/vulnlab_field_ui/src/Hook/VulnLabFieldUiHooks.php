<?php

declare(strict_types=1);

namespace Drupal\vulnlab_field_ui\Hook;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\vulnlab_field_ui\Gadget\LabGadgets;

/**
 * Hook implementations for vulnlab_field_ui.
 */
class VulnLabFieldUiHooks {

  /**
   * Implements hook_form_alter().
   *
   * Injects a row into the "Manage display" form whose '#region_callback' is
   * taken from the request. This is the ADMIN-ONLY path: core's own
   * "Manage display" screen is the sink, and the callback is whatever the
   * request asked for.
   *
   * The unauthenticated path lives in
   * Drupal\vulnlab_field_ui\Controller\PublicRceController.
   */
  #[Hook('form_alter')]
  public function formAlter(array &$form, FormStateInterface $form_state, string $form_id): void {
    if (!str_starts_with($form_id, 'entity_view_display_') && !str_starts_with($form_id, 'entity_form_display_')) {
      return;
    }
    if (!isset($form['fields']) || !is_array($form['fields'])) {
      return;
    }

    $request = \Drupal::request();
    $gadget = (string) ($request->query->get('vulnlab_gadget') ?? 'marker');
    $callable = LabGadgets::resolve($gadget);
    if ($callable === NULL) {
      return;
    }

    LabGadgets::setArgument((string) ($request->query->get('vulnlab_arg') ?? 'admin-path'));

    $form['fields']['vulnlab_row'] = [
      '#row_type' => 'field',
      // <<< The attacker-influenced value that core executes. >>>
      '#region_callback' => $callable,
      '#js_settings' => ['rowHandler' => 'field'],
      'human_name' => ['#plain_text' => 'Vuln lab row'],
      'machine_name' => ['#markup' => 'vulnlab_row'],
      'weight' => ['#type' => 'textfield', '#value' => 99, '#title' => 'Weight', '#title_display' => 'invisible'],
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
        'hidden_name' => ['#type' => 'hidden', '#value' => 'vulnlab_row'],
      ],
    ];
  }

}
