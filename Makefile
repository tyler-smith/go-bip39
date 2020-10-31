.DEFAULT_GOAL := help

.PHONY: tests profile_tests build_check
tests: ## Run tests with coverage
	@go test -v -coverprofile=coverage.out ./...

profile_tests: tests ## Run tests and output coverage profiling
	@go tool cover -html=coverage.out

build_check: ## Checks build and tests
	@go build . && go test -v -cover ./...

##
## Help
##
.DEFAULT_GOAL := help
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
