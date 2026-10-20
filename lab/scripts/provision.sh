#!/usr/bin/env bash
#
# Provisions the Drupal 11.4.9 vulnerability lab.
#
# Installs Drupal, enables the modules the three advisories need, and creates
# the content the PoCs operate on. Safe to re-run: it skips site:install if
# the site is already installed.
set -euo pipefail

DOCROOT="${DOCROOT:-/var/www/html/web}"
DB_HOST="${DRUPAL_DB_HOST:-db}"
DB_PORT="${DRUPAL_DB_PORT:-3306}"
DB_USER="${DRUPAL_DB_USER:-drupal}"
DB_PASS="${DRUPAL_DB_PASSWORD:-drupal}"
DB_NAME="${DRUPAL_DB_NAME:-drupal}"
DB_URL="mysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
LAB_PORT="${LAB_HTTP_PORT:-8080}"
SITE_URL="http://localhost:${LAB_PORT}"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

cd "$DOCROOT"

# ---------------------------------------------------------------------------
# Drush must live INSIDE the project.
#
# composer/installers places drupal/core outside vendor/ (at web/core), so a
# globally installed drush - which registers its own Composer\InstalledVersions
# - cannot see it and aborts with 'Package "drupal/core" is not installed'.
# Installing drush as a project dependency makes it share the project's
# autoloader, which is the standard arrangement.
# ---------------------------------------------------------------------------
PROJECT_ROOT="$(cd "${DOCROOT}/.." && pwd)"
DRUSH_BIN="${PROJECT_ROOT}/vendor/bin/drush"

if [ ! -x "${DRUSH_BIN}" ]; then
  log "Installing drush into the project"
  composer require --dev "drush/drush:^13" --no-interaction --no-progress --working-dir="${PROJECT_ROOT}" \
    || log "WARNING: could not install drush into the project"
fi

if [ -x "${DRUSH_BIN}" ]; then
  DRUSH="${DRUSH_BIN} --root=$DOCROOT"
else
  log "ERROR: no usable drush found"
  exit 1
fi

# ---------------------------------------------------------------------------
# Wait for the database.
# ---------------------------------------------------------------------------
log "Waiting for the database at ${DB_HOST}:${DB_PORT}"
for _ in $(seq 1 60); do
  if php -r 'try { new PDO("mysql:host=".$argv[1].";port=".$argv[2], $argv[3], $argv[4]); exit(0);} catch (Throwable $e) { exit(1);}' \
      "$DB_HOST" "$DB_PORT" "$DB_USER" "$DB_PASS" 2>/dev/null; then
    break
  fi
  sleep 2
done

# The lab modules are mounted read-only; make sure Drupal can still find them.
mkdir -p "${DOCROOT}/modules/custom"

# ---------------------------------------------------------------------------
# Install Drupal.
# ---------------------------------------------------------------------------
if $DRUSH status --field=bootstrap 2>/dev/null | grep -q "Successful"; then
  log "Drupal already installed - skipping site:install"
else
  log "Installing Drupal 11.4.9 (standard profile)"
  $DRUSH site:install standard \
    --db-url="$DB_URL" \
    --site-name="Drupal 11.4.9 Vulnerability Lab" \
    --account-name=admin \
    --account-pass=admin \
    --locale=en \
    --yes
fi

log "Configuring the site"
$DRUSH config:set system.site page.front /node --yes >/dev/null 2>&1 || true
$DRUSH config:set system.performance cache.page.max_age 0 --yes >/dev/null 2>&1 || true
$DRUSH config:set system.performance dynamic_page_cache 0 --yes >/dev/null 2>&1 || true
# JSON:API ships read-only; the lab needs to write link attributes.
$DRUSH config:set jsonapi.settings read_only 0 --yes >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Enable the modules the three advisories need.
# ---------------------------------------------------------------------------
log "Enabling modules"
$DRUSH pm:enable -y \
  field_ui \
  link \
  navigation \
  menu_link_content \
  jsonapi \
  big_pipe \
  vulnlab_field_ui \
  vulnlab_link \
  vulnlab_nav

# ---------------------------------------------------------------------------
# Lab content.
# ---------------------------------------------------------------------------
log "Creating lab content"

# A node type carrying a link field, so the Link field formatter (and thus
# Drupal\link\AttributeXss) is exercised on ordinary pages.
$DRUSH php:eval '
  if (!\Drupal\node\Entity\NodeType::load("vulnlab_article")) {
    \Drupal\node\Entity\NodeType::create([
      "type" => "vulnlab_article",
      "name" => "VulnLab Article",
    ])->save();
    \Drupal\field\Entity\FieldStorageConfig::create([
      "field_name" => "lab_link",
      "entity_type" => "node",
      "type" => "link",
    ])->save();
    \Drupal\field\Entity\FieldConfig::create([
      "field_name" => "lab_link",
      "entity_type" => "node",
      "bundle" => "vulnlab_article",
      "label" => "Lab link",
    ])->save();
  }
  // Use the lab widget and formatter so the editor can set raw attributes.
  \Drupal::service("entity_display.repository")->getFormDisplay("node", "vulnlab_article")->setComponent("lab_link", ["type" => "vulnlab_link_attributes", "weight" => 0])->save();
  \Drupal::service("entity_display.repository")->getViewDisplay("node", "vulnlab_article")->setComponent("lab_link", ["type" => "vulnlab_link_attributes", "label" => "above", "weight" => 0])->save();
'

# A low-privilege editor account. The Link field attributes are writable
# through the REST/JSON:API representation, so a plain content editor is
# enough to plant the payload.
if ! $DRUSH user:information labeditor --format=json 2>/dev/null | grep -q '"name"'; then
  $DRUSH user:create labeditor --mail=lab.editor@example.com >/dev/null
fi
$DRUSH user:password labeditor 'LabEditor!2026' >/dev/null
$DRUSH role:create editor >/dev/null 2>&1 || true
$DRUSH role:perm:add editor \
  "access content,create vulnlab_article content,edit any vulnlab_article content,administer menu,access administration pages,view the administration theme" >/dev/null
$DRUSH user-add-role editor labeditor >/dev/null

# A menu link whose TITLE carries the tooltip payload. The Navigation module
# copies the link title into data-drupal-tooltip, and the vulnerable
# tooltip.js re-parses it as markup.
$DRUSH php:eval '
  // The Navigation module keeps its menus in system.menu.* config.
  $menu = \Drupal::configFactory()->getEditable("system.menu.vulnlab");
  $menu->set("id", "vulnlab")->set("label", "VulnLab")->set("status", TRUE)
    ->set("dependencies", ["enforced" => ["module" => ["navigation"]]])->save();

  // Place the menu in the navigation layout so the toolbar renders it.
  $layout = \Drupal::configFactory()->getEditable("navigation.block_layout");
  $sections = $layout->get("sections");
  $components = $sections[0]["components"];
  $found = FALSE;
  foreach ($components as $component) {
    if (($component["configuration"]["id"] ?? "") === "navigation_menu:vulnlab") {
      $found = TRUE;
    }
  }
  if (!$found) {
    $uuid = \Drupal::service("uuid")->generate();
    $components[$uuid] = [
      "uuid" => $uuid,
      "region" => "content",
      "configuration" => [
        "id" => "navigation_menu:vulnlab",
        "label" => "VulnLab",
        "label_display" => "0",
        "provider" => "navigation",
        "level" => 1,
        "depth" => 2,
      ],
      "weight" => 3,
      "additional" => [],
    ];
    $sections[0]["components"] = $components;
    $layout->set("sections", $sections)->save();
  }

  $payload_title = "<img src=x onerror=\"window.__vulnlab_tooltip_xss=true\">";
  $link = \Drupal\menu_link_content\Entity\MenuLinkContent::load("vulnlab-tooltip-link");
  if (!$link) {
    $link = \Drupal\menu_link_content\Entity\MenuLinkContent::create([
      "link" => ["uri" => "http://example.com", "title" => "tooltip payload"],
    ]);
  }
  $link->set("title", $payload_title);
  $link->set("menu_name", "vulnlab");
  $link->set("enabled", TRUE);
  $link->save();
'

$DRUSH cache:rebuild

# The web server needs to be able to write to the private files directory.
chown -R www-data:www-data "${DOCROOT}/sites" 2>/dev/null || true

log "Lab ready"
cat <<EOF

  Site URL      : ${SITE_URL}
  Admin login   : admin / admin
  Editor login  : labeditor / LabEditor!2026

  F1 (RCE, unauthenticated) : ${SITE_URL}/vulnlab/field-ui-rce?gadget=marker&arg=hello
  F1 (RCE, admin only)      : ${SITE_URL}/admin/structure/types/manage/vulnlab_article/display/default?vulnlab_gadget=marker
  F2 (stored XSS)            : see docs/F2-link-htmx-xss.md
  F3 (stored XSS)            : see docs/F3-navigation-tooltip-xss.md

EOF
