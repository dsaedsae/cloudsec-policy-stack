# cloudsec-policy-stack — single entrypoint for the no-cluster + cluster tracks.
# Linux / macOS / GitHub Codespaces. (Windows: use the PowerShell scripts in scripts/.)

.DEFAULT_GOAL := help
PY := python

help:  ## list the targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  make %-10s %s\n", $$1, $$2}'

setup:  ## install the no-cluster deps (cedarpy, checkov, pyjwt, z3)
	$(PY) -m pip install -r requirements-dev.txt

doctor:  ## what is installed / missing
	bash scripts/doctor.sh

progress:  ## learning progress — auto-grade the no-cluster modules
	$(PY) scripts/progress.py

test:  ## the CI policy gate (5 suites, no cluster)
	$(PY) cedar/authz.py
	$(PY) cedar/agent_authz.py
	$(PY) app/api/auth_test.py
	$(PY) formal/cross_layer.py
	$(PY) scripts/check-sa-consistency.py

m0:  ## grade M0 (Cedar authz) — target 11/11
	$(PY) labs/m0/grade.py --ext
m1:  ## grade M1 (shift-left) — Failed checks 0
	$(PY) labs/m1/grade.py
m6:  ## grade M6 (agent-ABAC + ReBAC)
	$(PY) labs/m6/grade.py
m7:  ## run M7 (formal cross-layer consistency)
	$(PY) formal/cross_layer.py

brief:  ## regenerate the exec one-pager PDF from presentation/cloudsec-onepager.html (needs chrome/chromium)
	@b=$$(command -v chromium-browser chromium google-chrome chrome 2>/dev/null | head -1); \
	if [ -n "$$b" ]; then "$$b" --headless=new --disable-gpu --no-pdf-header-footer \
	  --print-to-pdf=presentation/cloudsec-onepager.pdf presentation/cloudsec-onepager.html && \
	  echo "-> presentation/cloudsec-onepager.pdf"; \
	else echo "no chrome/chromium found — open presentation/cloudsec-onepager.html and Ctrl-P -> Save as PDF"; fi

docs:  ## build the docs site (strict)
	$(PY) -m mkdocs build --strict

site:  ## build the deployable bundle (docs + the decision-maker landing) into site/ (see DEPLOY.md)
	$(PY) -m mkdocs build
	cp presentation/cloudsec-onepager.html site/cloudsec-onepager.html
	@cp presentation/cloudsec-onepager.pdf site/cloudsec-onepager.pdf 2>/dev/null || true
	@echo "-> site/ ready — drag to Netlify/Cloudflare, or see DEPLOY.md"
serve:  ## preview the docs site at http://localhost:8000
	$(PY) -m mkdocs serve

up:  ## stand up the kind cluster (M2-M5/M8 track; ~6-8GB RAM)
	bash scripts/up.sh
verify:  ## live enforcement suite (needs the cluster)
	bash scripts/verify.sh
down:  ## tear the cluster down (frees RAM)
	bash scripts/down.sh

.PHONY: help setup doctor progress test m0 m1 m6 m7 brief docs site serve up verify down
