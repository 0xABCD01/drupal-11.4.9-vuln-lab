# Drupal 11.4.9 vulnerability lab.
#
# The image deliberately ships the VULNERABLE Drupal 11.4.9 release so the
# three advisories below can be reproduced end to end:
#
#   SA-CORE-2026-014 / CVE-2026-108097  field_ui      RCE
#   SA-CORE-2026-015 / CVE-2026-108515  link          stored XSS
#   SA-CORE-2026-016 / CVE-2026-108514  navigation    stored XSS
#
# The Drupal project itself is NOT baked into the image: it is mounted from
# the host (see docker-compose.yml) so it can be replaced or inspected
# without rebuilding. The project uses the standard drupal/recommended-project
# layout, whose document root is <project>/web.
#
# Everything runs locally. Do NOT point this image at anything you do not own.
FROM drupal:11.4.9

# A fallback drush. The real one is installed INTO the project during
# provisioning: composer/installers places drupal/core outside vendor/, so a
# globally installed drush cannot see it.
RUN composer global require drush/drush:^13 --no-interaction --no-progress \
 && ln -sf /root/.composer/vendor/bin/drush /usr/local/bin/drush

# The composer project keeps the document root in 'web/', but this image's
# Apache is rooted at /var/www/html. Point Apache at the real docroot and
# allow Drupal's .htaccess (clean URLs) to work.
ENV APACHE_DOCUMENT_ROOT=/var/www/html/web
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && printf '<Directory %s>\n\tAllowOverride All\n\tRequire all granted\n</Directory>\n' \
      "$APACHE_DOCUMENT_ROOT" > /etc/apache2/conf-available/drupal-lab.conf \
 && a2enconf drupal-lab

WORKDIR /var/www/html
