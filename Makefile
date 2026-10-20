PY := .venv/bin/python
PIP := .venv/bin/pip

# Local development database. The password is a development one and is meant to be
# seen: a real node reads its DSN from a 0600 file via systemd LoadCredential, never
# from a Makefile or the environment. See deploy/env/credentials.README.md.
PG_CLUSTER ?= 16 main
DEV_DSN ?= postgres://alerting_owner:devpass@127.0.0.1:5432/alerting
export ALERTING_DSN ?= $(DEV_DSN)

.PHONY: setup test lint typecheck demo org-init serve clean db-up db-down db-reset

setup:
	python3 -m venv .venv
	$(PIP) install -q -e ".[dev]"

# Starts the cluster and creates the two roles. Idempotent: safe to re-run.
db-up:
	pg_ctlcluster $(PG_CLUSTER) start || true
	@until pg_isready -q; do sleep 0.2; done
	@su postgres -c "psql -q -v ON_ERROR_STOP=1" < deploy/postgres/dev-bootstrap.sql
	$(PY) -m alerting.server.cli migrate
	@echo "database ready: $(DEV_DSN)"

db-down:
	pg_ctlcluster $(PG_CLUSTER) stop || true

# Drops the schema and migrates from scratch. On PostgreSQL this needs the owner
# role; it used to be `rm var/alerting.db`.
db-reset:
	@su postgres -c "psql -q -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS alerting'"
	@$(MAKE) --no-print-directory db-up

test:
	.venv/bin/pytest -q --cov=alerting.core --cov-report=term-missing --cov-fail-under=95

lint:
	.venv/bin/ruff check src tests scripts
	.venv/bin/ruff format --check src tests scripts

typecheck:
	.venv/bin/mypy src/alerting/core

org-init:
	$(PY) scripts/org_init.py --i-understand-this-is-a-demo

demo:
	$(PY) scripts/demo_e2e.py

serve:
	.venv/bin/alerting-server --host 127.0.0.1 --port 8080

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage var/heads var/demo
