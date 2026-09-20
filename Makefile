PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: setup test lint typecheck demo org-init serve clean

setup:
	python3 -m venv .venv
	$(PIP) install -q -e ".[dev]"

test:
	.venv/bin/pytest -q --cov=alerting.core --cov-report=term-missing --cov-fail-under=95

lint:
	.venv/bin/ruff check src tests scripts
	.venv/bin/ruff format --check src tests scripts

typecheck:
	.venv/bin/mypy src/alerting/core

org-init:
	$(PY) scripts/org_init.py

demo:
	$(PY) scripts/demo_e2e.py

serve:
	.venv/bin/uvicorn alerting.server.app:create_app --factory --host 127.0.0.1 --port 8080

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage var/*.db var/heads
