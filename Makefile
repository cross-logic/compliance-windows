.PHONY: test build-stig build-cis build-all install lint clean help

COLLECTION_NAMESPACE = security
COLLECTION_NAME = compliance_windows
COLLECTION_VERSION = $(shell grep '^version:' galaxy.yml | awk '{print $$2}')

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

test: ## Run unit tests
	python3 -m pytest tests/ -v

lint: ## Run ansible-lint
	ansible-lint

build-collection: ## Build collection tarball
	ansible-galaxy collection build --force --output-path build/
	@echo "Built: build/$(COLLECTION_NAMESPACE)-$(COLLECTION_NAME)-$(COLLECTION_VERSION).tar.gz"

build-stig: ## Build STIG Execution Environment
	./scripts/build-ee.sh stig

build-cis: ## Build CIS Execution Environment
	./scripts/build-ee.sh cis

build-all: ## Build all Execution Environments
	./scripts/build-ee.sh all

install: ## Register profile on AAP Controller (requires AAP_HOST + AAP_API_TOKEN)
	ansible-playbook install.yml

uninstall: ## Disconnect profile from AAP Controller
	ansible-playbook uninstall.yml

clean: ## Remove build artifacts
	rm -rf build/ .pytest_cache/ plugins/filter/__pycache__/ plugins/modules/__pycache__/
