#!/usr/bin/env bash
#
# Populates ./drupal with a vulnerable Drupal 11.4.9 project.
#
# The project uses the standard drupal/recommended-project layout:
#
#   ./drupal/vendor      composer dependencies
#   ./drupal/web         the document root (core, modules, themes, sites)
#
# That is what the drupal:11.4.9 image expects and what drush detects, so
# no Apache reconfiguration beyond the image's own APACHE_DOCUMENT_ROOT is
# needed.
#
# Usage:
#   ./lab/scripts/fetch-drupal.sh                 # build it with composer
#   ./lab/scripts/fetch-drupal.sh /path/to/project # copy an existing project
#
# Environment:
#   DRUPAL_VERSION  Drupal version to install (default 11.4.9)
#   CONTAINER_TOOL  podman (default) or docker
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${REPO_ROOT}/drupal"
DRUPAL_VERSION="${DRUPAL_VERSION:-11.4.9}"
CONTAINER_TOOL="${CONTAINER_TOOL:-podman}"
SOURCE_TREE="${1:-${DRUPAL_TREE:-}}"

log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }

if [ -f "${TARGET}/web/core/lib/Drupal.php" ]; then
  log "Project already present at ${TARGET}"
  grep -m1 "const VERSION" "${TARGET}/web/core/lib/Drupal.php" || true
  exit 0
fi

# ---------------------------------------------------------------------------
# Option A: copy an existing project.
# ---------------------------------------------------------------------------
if [ -n "${SOURCE_TREE}" ] && [ -f "${SOURCE_TREE}/web/core/lib/Drupal.php" ]; then
  log "Copying the Drupal project from ${SOURCE_TREE}"
  mkdir -p "${TARGET}"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "${SOURCE_TREE}/" "${TARGET}/"
  else
    cp -a "${SOURCE_TREE}/." "${TARGET}/"
  fi
  log "Verifying version"
  grep -m1 "const VERSION" "${TARGET}/web/core/lib/Drupal.php"
  if ! grep -q "const VERSION = '${DRUPAL_VERSION}'" "${TARGET}/web/core/lib/Drupal.php"; then
    log "WARNING: the copied project is not Drupal ${DRUPAL_VERSION}"
  fi
  exit 0
fi

if [ -n "${SOURCE_TREE}" ] && [ -f "${SOURCE_TREE}/core/lib/Drupal.php" ]; then
  log "ERROR: ${SOURCE_TREE} uses the drupal/drupal layout (core at the project root)."
  log "       The lab needs the drupal/recommended-project layout (core under web/)."
  log "       Let the script build one instead:  ./lab/scripts/fetch-drupal.sh"
  exit 1
fi

# ---------------------------------------------------------------------------
# Option B: build it with composer inside a throwaway container.
# ---------------------------------------------------------------------------
log "Creating the Drupal ${DRUPAL_VERSION} project with composer"

mkdir -p "${TARGET}"
# The composer cache lives outside the project so re-runs are fast.
mkdir -p "${REPO_ROOT}/.cache/composer"

"${CONTAINER_TOOL}" run --rm \
  -v "${TARGET}:/w" \
  -v "${REPO_ROOT}/.cache/composer:/composer-cache" \
  -e COMPOSER_CACHE_DIR=/composer-cache \
  -w /w \
  "docker.io/library/drupal:${DRUPAL_VERSION}" \
  composer create-project "drupal/recommended-project:${DRUPAL_VERSION}" . \
    --no-interaction --no-progress

log "Verifying version"
grep -m1 "const VERSION" "${TARGET}/web/core/lib/Drupal.php"

log "Done: ${TARGET}"
