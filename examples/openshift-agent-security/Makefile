# SPDX-License-Identifier: Apache-2.0
PYTHON ?= python3
export PYTHONPATH := runtime:runtime/identity_demo:scripts/identity_demo:tests/identity_demo
.PHONY: test check
test:
	$(PYTHON) -m pytest -q
check:
	$(PYTHON) scripts/verify-source.py --inventory
	$(PYTHON) scripts/check-public-safety.py
