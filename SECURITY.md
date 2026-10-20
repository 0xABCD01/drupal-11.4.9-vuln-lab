# Security Policy

## Scope of this repository

This is an **educational lab** for three Drupal core advisories that are
already public and already fixed upstream:

| Advisory | CVE | Fixed in |
|----------|-----|----------|
| SA-CORE-2026-014 | CVE-2026-108097 | Drupal 11.4.10 |
| SA-CORE-2026-015 | CVE-2026-108515 | Drupal 11.4.10 |
| SA-CORE-2026-016 | CVE-2026-108514 | Drupal 11.4.10 |

The lab modules (`lab/modules/vulnlab_*`) are **intentionally vulnerable
by design** — they exist to make the core defects reachable so they can be
studied. Do not deploy them anywhere but a throwaway local container.

## Deliberate safety limits

The lab is written so it cannot easily be turned into a weapon:

* The F1 gadget registry (`vulnlab_field_ui`) exposes only `marker`,
  `exec` (three allow-listed commands: `id`, `whoami`, `uname -a`) and
  `sleep`. There is **no** arbitrary-command or arbitrary-callable endpoint.
* `lab/standalone/f1_gadget_chain.php` demonstrates the full
  write -> `.htaccess` -> RCE chain. It confines every path to the lab's own
  Drupal root, backs up `sites/default/files/.htaccess`, and restores it on
  `--cleanup`. `lab/scripts/f1-chain.sh` always cleans up, even on failure.
* The F2 widget (`vulnlab_link`) only writes attributes the editor typed;
  it does not inject anything on its own.
* The F3 controller only reflects a value into a `data-drupal-tooltip`
  attribute on a local page.
* Nothing in this repository scans, probes or exploits anything outside the
  Docker network it starts.

## Reporting a problem with the lab

If you find a bug in the **lab code** (the PoCs, the modules, the compose
setup), open an issue. Please do not report the underlying Drupal
vulnerabilities here — they belong to the Drupal Security Team
(`security@drupal.org`), who disclosed them and assigned the CVEs.

## Using this against a third-party site

Don't. These PoCs are written for a local lab. If you need to assess whether
a site you are **authorised** to test is affected, use the passive checks in
`docs/` instead:

* **F1** — is the `field_ui` module installed? (`drush pm:list --status=enabled --filter=field_ui`)
  Does any contributed module alter the entity view/form display form?
* **F2** — render a page with a link field and inspect the delivered HTML for
  `hx-` / `data-hx-` attributes on `<a>` elements.
* **F3** — check whether a menu link title containing `<` appears in a
  `data-drupal-tooltip` attribute.

## Hardening reminder

Upgrade to Drupal 11.4.10 (or 11.3.19 / 10.6.19). Until then, the Drupal
Security Team's own mitigation for SA-CORE-2026-014 is to **uninstall the
`field_ui` module**.
