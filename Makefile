APP ?= memos

ifneq ($(APP),memos)
$(error Unknown APP '$(APP)'; available applications: memos)
endif

.PHONY: check test integration package tools verify-image gateway-probe-test gateway-probe-package gateway-probe-smoke auth-feasibility auth-test auth-integration
check test integration package tools verify-image gateway-probe-test gateway-probe-package gateway-probe-smoke auth-feasibility auth-test auth-integration:
	$(MAKE) --no-print-directory -C apps/$(APP) $@
