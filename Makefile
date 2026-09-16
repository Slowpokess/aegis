.PHONY: install test test-offline test-integration run migrate lab-up lab-down rust-build rust-test phase2-test phase3-test phase4-test phase5-test phase6-test phase7-test phase8-test phase9-test phase10-test phase11-test phase12-test phase13-test phase14-test

PYTHON ?= .venv/bin/python
RUST_TOOLCHAIN_BIN := $(dir $(shell rustup which rustc))
RUST_PATH := $(RUST_TOOLCHAIN_BIN):/usr/bin:/bin

install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest

test-offline:
	$(PYTHON) -m pytest -m "not network_integration"

test-integration:
	$(PYTHON) -m pytest -m network_integration

run:
	$(PYTHON) -m uvicorn app.main:app --host 127.0.0.1 --port 8000

migrate:
	$(PYTHON) -m alembic upgrade head

lab-up:
	docker compose -f lab/docker-compose.yml up --build --detach --wait

lab-down:
	docker compose -f lab/docker-compose.yml down

rust-build:
	PATH="$(RUST_PATH)" cargo build --manifest-path native/rust/Cargo.toml --workspace

rust-test:
	cd native/rust && PATH="$(RUST_PATH)" cargo fmt --all --check
	PATH="$(RUST_PATH)" cargo clippy --manifest-path native/rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
	PATH="$(RUST_PATH)" cargo test --manifest-path native/rust/Cargo.toml --workspace

phase2-test: rust-test
	$(PYTHON) -m pytest
	/Library/Frameworks/Python.framework/Versions/3.12/bin/ruff check app lab migrations tests
	$(PYTHON) -m compileall -q app lab migrations tests

phase3-test: rust-test
	$(PYTHON) -m pytest
	/Library/Frameworks/Python.framework/Versions/3.12/bin/ruff check app lab migrations tests
	$(PYTHON) -m compileall -q app lab migrations tests

phase4-test: rust-test
	$(PYTHON) -m pytest
	/Library/Frameworks/Python.framework/Versions/3.12/bin/ruff check app lab migrations tests
	$(PYTHON) -m compileall -q app lab migrations tests

phase5-test: phase4-test

phase6-test: rust-test
	$(PYTHON) -m pytest
	/Library/Frameworks/Python.framework/Versions/3.12/bin/ruff check app evals lab migrations tests scripts
	$(PYTHON) -m compileall -q app evals lab migrations tests scripts

phase7-test: phase6-test

phase8-test: phase7-test

phase9-test: phase8-test

phase10-test: phase9-test

phase11-test: phase10-test

phase12-test: phase11-test

phase13-test: phase12-test

phase14-test: phase13-test
	cd web && npm run typecheck && npm run lint && npm run test && npm run build
