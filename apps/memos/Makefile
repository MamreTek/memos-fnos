PYTHON ?= python3
FNPACK ?= .cache/fnpack

.PHONY: check test integration package tools verify-image
check:
	$(PYTHON) scripts/check.py
test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
integration:
	$(PYTHON) tests/integration.py
tools:
	$(PYTHON) scripts/fetch_fnpack.py
verify-image:
	$(PYTHON) scripts/verify_image.py
package: check
	$(PYTHON) scripts/package.py --fnpack "$(FNPACK)"
