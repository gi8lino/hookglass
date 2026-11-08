.DEFAULT_GOAL := help

## Tool Versions

# renovate: datasource=github-releases depName=golangci/golangci-lint
GOLANGCI_LINT_VERSION ?= v2.15.0

# renovate: datasource=github-releases depName=gi8lino/dev-tools
DEV_TOOLS_VERSION ?= v0.9.0

## Shared development tools

include bin/dev-tools.mk
include $(call dev-tools-module,tag)
include $(call dev-tools-module,port)
include $(call dev-tools-module,help)

## Project-local tools

GOLANGCI_LINT := bin/golangci-lint

## Build Configuration

BINARY ?= build/hookglass
COMMAND ?= ./cmd/hookglass
BUILD_VERSION ?= dev
LDFLAGS ?= -s -w -X main.Version=$(BUILD_VERSION)

## Local Development

CONFIG ?=
HOOKGLASS_ASSIGNED_PORT ?= $(call dev-port,app)
LISTEN_ADDRESS ?= 127.0.0.1:$(HOOKGLASS_ASSIGNED_PORT)
RUN_ARGS ?=

##@ Development

.PHONY: ports
ports: $(DEV_PORT) ## Print the assigned local HTTP port.
	@$(DEV_PORT) app --port "$(HOOKGLASS_ASSIGNED_PORT)" > /dev/null
	@echo "Echo:   http://127.0.0.1:$(HOOKGLASS_ASSIGNED_PORT)/echo"
	@echo "HMAC:   http://127.0.0.1:$(HOOKGLASS_ASSIGNED_PORT)/hmac"
	@echo "Header: http://127.0.0.1:$(HOOKGLASS_ASSIGNED_PORT)/header"
	@echo "Bearer: http://127.0.0.1:$(HOOKGLASS_ASSIGNED_PORT)/bearer"
	@echo "Health: http://127.0.0.1:$(HOOKGLASS_ASSIGNED_PORT)/healthz"

.PHONY: ports-reset
ports-reset: $(DEV_PORT) ## Clear saved ports after stopping local services.
	$(call run-tool,$(DEV_PORT),--reset)

.PHONY: download
download: dev-tools ## Download Go modules and development tools.
	go mod download

.PHONY: build
build: ## Build the Hookglass binary.
	@mkdir -p "$(dir $(BINARY))"
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o "$(BINARY)" "$(COMMAND)"

.PHONY: serve
serve: ports ## Run Hookglass with an optional YAML configuration.
	go run "$(COMMAND)" $(if $(strip $(CONFIG)),--config="$(CONFIG)") \
		--listen-address="$(LISTEN_ADDRESS)" \
		$(RUN_ARGS)

.PHONY: run
run: ## Run Hookglass locally and print the webhook endpoints.
	$(MAKE) serve CONFIG="$(CONFIG)" RUN_ARGS="$(RUN_ARGS)"

.PHONY: clean
clean: ## Remove build outputs and coverage reports.
	rm -rf build
	rm -f coverage.out coverage.html

##@ Testing

.PHONY: test
test: ## Run Go tests.
	go test -count=1 -timeout=3m ./...

.PHONY: test-race
test-race: ## Run Go tests with the race detector.
	go test -race -count=1 -timeout=3m ./...

.PHONY: cover
cover: ## Generate and view Go test coverage.
	go test -coverprofile=coverage.out -covermode=set -count=1 -timeout=3m ./...
	go tool cover -html=coverage.out

##@ Formatting

.PHONY: fmt
fmt: ## Format Go source code.
	go fmt ./...

.PHONY: check-format
check-format: ## Verify Go source formatting and whitespace.
	@unformatted="$$(gofmt -l cmd internal)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files need formatting:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi
	git diff --check

##@ Linting

.PHONY: vet
vet: ## Run Go static analysis.
	go vet ./...

.PHONY: lint
lint: lint-go ## Run Go linters.

.PHONY: lint-go
lint-go: golangci-lint ## Run golangci-lint.
	$(call run-tool,$(GOLANGCI_LINT),run)

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint and apply fixes.
	$(call run-tool,$(GOLANGCI_LINT),run --fix)

.PHONY: check
check: check-format vet test-race ## Run formatting, vet and race checks.

.PHONY: verify
verify: check lint ## Run all local checks.

##@ Dependencies

.PHONY: dev-tools
dev-tools: $(DEV_PORT) $(DEV_TAG) $(MAKE_HELP) $(GO_INSTALL_TOOL) ## Download the pinned development tools.

.PHONY: golangci-lint
golangci-lint: $(GO_INSTALL_TOOL) ## Download golangci-lint locally if necessary.
	@$(GO_INSTALL_TOOL) \
		--target "$(GOLANGCI_LINT)" \
		--package github.com/golangci/golangci-lint/v2/cmd/golangci-lint \
		--tool-version "$(GOLANGCI_LINT_VERSION)"
