<?php

declare(strict_types=1);

namespace Drupal\vulnlab_link\Plugin\Field\FieldWidget;

use Drupal\Core\Field\Attribute\FieldWidget;
use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\link\Plugin\Field\FieldWidget\LinkWidget;

/**
 * A link widget that also lets the editor set raw HTML attributes.
 *
 * This plays the role of the very common contributed modules that expose
 * arbitrary link attributes to content editors. The core Link widget
 * deliberately hides them ("Exposing the attributes array in the widget is
 * left for alternate and more advanced field widgets." -
 * core/modules/link/src/Plugin/Field/FieldWidget/LinkWidget.php:339-344).
 *
 * The attributes end up in the link item's 'options' map, which is what
 * Drupal\link\AttributeXss::sanitizeAttributes() is supposed to clean. In
 * Drupal 11.4.9 it does not strip the htmx attribute families, so
 * "hx-on-click" survives all the way into the rendered page.
 */
#[FieldWidget(
  id: "vulnlab_link_attributes",
  label: new \Drupal\Core\StringTranslation\TranslatableMarkup("Link (vuln lab: with attributes)"),
  field_types: ["link"],
)]
class VulnLabLinkWidget extends LinkWidget {

  /**
   * {@inheritdoc}
   */
  public function formElement(FieldItemListInterface $items, $delta, array $element, array &$form, FormStateInterface $form_state) {
    $element = parent::formElement($items, $delta, $element, $form, $form_state);

    $item = $items[$delta];
    $existing = [];
    if (!$item->isEmpty() && !empty($item->options['attributes'])) {
      $existing = array_map(
        static fn ($v) => is_array($v) ? implode(' ', $v) : (string) $v,
        $item->options['attributes']
      );
    }

    $element['lab_attributes'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Link attributes (vuln lab)'),
      '#description' => $this->t('One attribute per line, as <code>name=value</code>. Example: <code>hx-on-click=alert(document.domain)</code>.'),
      '#default_value' => $existing ? implode("\n", $existing) : '',
      '#rows' => 3,
    ];

    return $element;
  }

  /**
   * {@inheritdoc}
   */
  public function massageFormValues(array $values, array $form, FormStateInterface $form_state) {
    $values = parent::massageFormValues($values, $form, $form_state);

    foreach ($values as &$value) {
      if (empty($value['lab_attributes'])) {
        unset($value['lab_attributes']);
        continue;
      }
      $attributes = $value['options']['attributes'] ?? [];
      foreach (self::parseAttributes((string) $value['lab_attributes']) as $name => $attribute_value) {
        $attributes[$name] = $attribute_value;
      }
      $value['options']['attributes'] = $attributes;
      unset($value['lab_attributes']);
    }

    return $values;
  }

  /**
   * Parses "name=value" lines into an attribute map.
   *
   * @param string $raw
   *   The raw textarea value.
   *
   * @return array
   *   Attribute name => value.
   */
  public static function parseAttributes(string $raw): array {
    $attributes = [];
    foreach (preg_split('/\R/', $raw) as $line) {
      $line = trim($line);
      if ($line === '' || !str_contains($line, '=')) {
        continue;
      }
      [$name, $value] = explode('=', $line, 2);
      $name = trim($name);
      if ($name === '') {
        continue;
      }
      $attributes[$name] = trim($value, " \t\"'");
    }
    return $attributes;
  }

}
