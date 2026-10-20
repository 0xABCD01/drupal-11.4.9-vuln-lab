<?php

declare(strict_types=1);

namespace Drupal\vulnlab_link\Hook;

use Drupal\Core\Hook\Attribute\Hook;

/**
 * Hook implementations for vulnlab_link.
 */
class VulnLabLinkHooks {

  /**
   * Implements hook_page_attachments().
   *
   * Attaches Drupal's htmx integration to pages that show the lab content
   * type.
   *
   * Why this is needed: the htmx ATTRIBUTE is emitted into the page
   * unconditionally (that is the bug), but it only becomes executable
   * JavaScript when the htmx runtime is present. Drupal 11.4 ships htmx
   * 2.0.4 and has first class htmx support - Drupal\Core\Htmx\Htmx, the
   * 'drupal_htmx' wrapper format and the 'core/drupal.htmx' library - so a
   * site that navigates with htmx loads it on every page.
   *
   * The lab reproduces that situation, because otherwise the finding would
   * stop at "an unexpected attribute is present in the HTML".
   */
  #[Hook('page_attachments')]
  public function pageAttachments(array &$attachments): void {
    $node = \Drupal::routeMatch()->getParameter('node');
    if ($node instanceof \Drupal\node\NodeInterface && $node->bundle() === 'vulnlab_article') {
      $attachments['#attached']['library'][] = 'core/drupal.htmx';
    }
  }

}
