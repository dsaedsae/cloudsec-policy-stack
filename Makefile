# cloudsec-policy-stack — single entrypoint for the no-cluster + cluster tracks.
# Linux / macOS / GitHub Codespaces. (Windows: use the PowerShell scripts in scripts/.)

.DEFAULT_GOAL := help
# Prefer the project venv if present (so `make m7` / `make test` get z3/cedarpy without
# needing the venv activated); fall back to bare python (e.g. Codespaces after `make setup`).
PY := $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python)

help:  ## list the targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  make %-10s %s\n", $$1, $$2}'

venv:  ## create the project .venv (Python 3.12)
	python3 -m venv .venv

setup: ## create .venv if missing, then install the no-cluster deps (cedarpy, checkov, pyjwt, z3)
	@test -d .venv || python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements-dev.txt

doctor:  ## what is installed / missing
	bash scripts/doctor.sh

progress:  ## learning progress — auto-grade the no-cluster modules
	$(PY) scripts/progress.py

test:  ## the CI policy gate (no cluster)
	$(PY) cedar/authz.py
	$(PY) cedar/agent_authz.py
	$(PY) app/api/auth_test.py
	$(PY) formal/cross_layer.py
	$(PY) formal/cross_layer_test.py
	$(PY) scripts/check-sa-consistency.py

m0:  ## grade M0 (Cedar authz) — target 11/11
	$(PY) labs/m0/grade.py --ext
m1:  ## grade M1 (shift-left) — Failed checks 0
	$(PY) labs/m1/grade.py
m6:  ## grade M6 (agent-ABAC + ReBAC)
	$(PY) labs/m6/grade.py
m7:  ## run M7 (formal cross-layer consistency)
	$(PY) formal/cross_layer.py

report:  ## cross-layer-lint -> outputs/cross-layer/report.{json,sarif,html} (HTML for humans, SARIF for code-scanning)
	$(PY) formal/cross_layer.py --out outputs/cross-layer
	@echo "-> outputs/cross-layer/report.html  (open in a browser) · report.sarif (GitHub code scanning) · report.json"

brief:  ## regenerate the exec one-pager PDF from presentation/cloudsec-onepager.html (needs chrome/chromium)
	@b=$$(command -v chromium-browser chromium google-chrome chrome 2>/dev/null | head -1); \
	if [ -n "$$b" ]; then "$$b" --headless=new --disable-gpu --no-pdf-header-footer \
	  --print-to-pdf=presentation/cloudsec-onepager.pdf presentation/cloudsec-onepager.html && \
	  echo "-> presentation/cloudsec-onepager.pdf"; \
	else echo "no chrome/chromium found — open presentation/cloudsec-onepager.html and Ctrl-P -> Save as PDF"; fi

docs:  ## build the docs site (strict)
	DISABLE_MKDOCS_2_WARNING=true NO_MKDOCS_2_WARNING=true $(PY) -m mkdocs build --strict

site:  ## build the all-HTML deployable bundle into site/ (landing = root; docs = HTML) — see DEPLOY.md
	DISABLE_MKDOCS_2_WARNING=true NO_MKDOCS_2_WARNING=true $(PY) -m mkdocs build
	cp presentation/cloudsec-onepager.html site/cloudsec-onepager.html
	cp presentation/curriculum.html site/curriculum.html
	@cp presentation/cloudsec-onepager.pdf site/cloudsec-onepager.pdf 2>/dev/null || true
	cp presentation/cloudsec-onepager.html site/index.html
	@# in the DEPLOYED root copy only, upgrade the practice button's href from the GitHub labs URL
	@# to the in-site HTML hub (better UX, keeps the visitor on-site). If this no-ops, the source
	@# GitHub URL still works -- keep this match-string in sync with the href in cloudsec-onepager.html.
	@sed -i 's#href="https://github.com/dsaedsae/cloudsec-policy-stack/tree/master/labs"#href="labs/"#' site/index.html 2>/dev/null || true
	@echo "-> site/ : index.html = 의사결정자 랜딩, /labs /docs = 전부 HTML 문서. DEPLOY.md 참고."
serve:  ## preview the docs site at http://localhost:8000
	$(PY) -m mkdocs serve

up:  ## stand up the kind cluster (M2-M5/M8 track; ~6-8GB RAM)
	bash scripts/up.sh
verify:  ## live enforcement suite (needs the cluster)
	bash scripts/verify.sh
down:  ## tear the cluster down (frees RAM)
	bash scripts/down.sh

.PHONY: help venv setup doctor progress test m0 m1 m6 m7 report brief docs site serve up verify down
