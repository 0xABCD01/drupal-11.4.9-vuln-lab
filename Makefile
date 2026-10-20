# Drupal 11.4.9 vulnerability lab — convenience targets.
#
#   make up        build the image, start db+web, provision the site
#   make poc       run every end-to-end PoC
#   make standalone run the zero-dependency PoCs (needs DRUPAL_ROOT)
#   make down      stop everything
#   make clean     stop everything and delete the local Drupal project

SHELL := /bin/bash
COMPOSE ?= docker compose
DRUPAL_VERSION ?= 11.4.9
LAB_HTTP_PORT ?= 8080

.PHONY: help up down clean poc standalone logs fetch rebuild

help:
	@echo "Targets:"
	@echo "  fetch       populate ./drupal with a vulnerable Drupal $(DRUPAL_VERSION)"
	@echo "  up          build the image, start db+web, provision the lab"
	@echo "  poc         run every end-to-end PoC"
	@echo "  standalone  run the zero-dependency PoCs (set DRUPAL_ROOT)"
	@echo "  down        stop the stack"
	@echo "  clean       stop the stack and delete ./drupal"

fetch:
	DRUPAL_VERSION=$(DRUPAL_VERSION) ./lab/scripts/fetch-drupal.sh

up: fetch
	$(COMPOSE) up -d --build db web
	$(COMPOSE) run --rm provision
	@echo ""
	@echo "  Lab ready: http://localhost:$(LAB_HTTP_PORT)"
	@echo "  admin / admin      |  labeditor / LabEditor!2026"

down:
	$(COMPOSE) down

clean: down
	rm -rf ./drupal
	$(COMPOSE) down -v

poc:
	LAB_URL=http://localhost:$(LAB_HTTP_PORT) python3 lab/poc/run_all.py

standalone:
	@test -n "$$DRUPAL_ROOT" || (echo "set DRUPAL_ROOT=/path/to/drupal-$(DRUPAL_VERSION)"; exit 1)
	php lab/standalone/f1_field_ui_rce.php
	php lab/standalone/f2_attribute_xss.php
	node lab/standalone/f3_tooltip_xss.js

logs:
	$(COMPOSE) logs -f web

rebuild:
	$(COMPOSE) build --no-cache
