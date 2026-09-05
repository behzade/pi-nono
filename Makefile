BUMP ?= patch

.PHONY: release
release:
	node packaging/npm/release.mjs "$(BUMP)"
