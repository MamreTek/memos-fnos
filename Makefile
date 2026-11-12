APP ?= memos

ifneq ($(APP),memos)
$(error Unknown APP '$(APP)'; available applications: memos)
endif

.PHONY: check test integration package tools verify-image
check test integration package tools verify-image:
	$(MAKE) --no-print-directory -C apps/$(APP) $@
