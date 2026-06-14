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

docs:  ## build the docs site (strict)
	$(PY) -m mkdocs build --strict
serve:  ## preview the docs site at http://localhost:8000
	$(PY) -m mkdocs serve

up:  ## stand up the kind cluster (M2-M5/M8 track; ~6-8GB RAM)
	bash scripts/up.sh
verify:  ## live enforcement suite (needs the cluster)
	bash scripts/verify.sh
down:  ## tear the cluster down (frees RAM)
	bash scripts/down.sh

.PHONY: help setup doctor progress test m0 m1 m6 m7 docs serve up verify down
