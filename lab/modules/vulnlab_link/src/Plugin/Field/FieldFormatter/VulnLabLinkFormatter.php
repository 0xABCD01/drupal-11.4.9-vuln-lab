<?php

declare(strict_types=1);

namespace Drupal\vulnlab_link\Plugin\Field\FieldFormatter;

use Drupal\Core\Field\Attribute\FieldFormatter;
use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\link\Plugin\Field\FieldFormatter\LinkFormatter;

/**
 * A link formatter that reports which attributes survived sanitisation.
 *
 * Drupal\link\AttributeXss::sanitizeAttributes() is applied by the parent
 * LinkFormatter (core/modules/link/src/Plugin/Field/FieldFormatter/LinkFormatter.php:246)
 * before the URL is built. This formatter reports what actually made it
 * through, so a lab user can see the difference between "the editor submitted
 * it" and "Drupal emitted it".
 */
#[FieldFormatter(
  id: "vulnlab_link_attributes",
  label: new TranslatableMarkup("Link (vuln lab: show emitted attributes)"),
  field_types: ["link"],
)]
class VulnLabLinkFormatter extends LinkFormatter {

  /**
   * {@inheritdoc}
   */
  public function viewElements(FieldItemListInterface $items, $langcode) {
    $elements = parent::viewElements($items, $langcode);

    foreach ($elements as $delta => $element) {
      if (!isset($element['#url'])) {
        continue;
      }
      $attributes = $element['#url']->getOption('attributes') ?? [];
      if (!$attributes) {
        continue;
      }
      $emitted = [];
      foreach ($attributes as $name => $value) {
        $emitted[] = $name . '=' . (is_array($value) ? implode(' ', $value) : (string) $value);
      }
      $element['#attributes']['data-vulnlab-emitted-attributes'] = implode(' | ', $emitted);
      $element['#attributes']['data-vulnlab-htmx-attribute'] = 'yes';
      $elements[$delta] = $element;
    }

    return $elements;
  }

}
