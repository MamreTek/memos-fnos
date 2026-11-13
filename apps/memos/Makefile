PYTHON ?= python3
FNPACK ?= .cache/fnpack

.PHONY: check test integration package tools verify-image gateway-probe-test gateway-probe-package gateway-probe-smoke auth-feasibility auth-test auth-integration
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
gateway-probe-test:
	cd tests/fnos-gateway-probe && go test -race ./... && go vet ./...
	$(PYTHON) tests/fnos-gateway-probe/lifecycle_test.py
gateway-probe-package:
	$(PYTHON) tests/fnos-gateway-probe/build.py --fnpack "$(FNPACK)"
gateway-probe-smoke:
	$(PYTHON) tests/fnos-gateway-probe/package_smoke.py
auth-feasibility:
	$(PYTHON) tests/auth_feasibility.py
auth-test:
	cd auth-bridge && go test -race ./... && go vet ./...
auth-integration:
	test -n "$$MEMOS_BINARY"
	cd auth-bridge && go test -race ./internal/oauthbridge -run '^TestRealMemosIntegration$$' -count=1 -v -timeout=2m
