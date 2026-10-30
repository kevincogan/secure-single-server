# SPDX-License-Identifier: Apache-2.0
PYTHON ?= python3
IMAGE ?= service-request-demo:development
ENGINE ?= docker
export PYTHONPATH := ../../../runtime

.PHONY: test lint run build
test:
	$(PYTHON) -m pytest tests -q
lint:
	ruff check src tests
run:
	$(PYTHON) src/client.py
build:
	$(PYTHON) ../../../scripts/build-agent.py --engine $(ENGINE) --image $(IMAGE)
