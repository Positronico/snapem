# snapem Makefile

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build install clean test lint fmt help

all: build

## Build

build: ## Build the binary
	go build -ldflags "$(LDFLAGS)" -o bin/snapem ./cmd/snapem

build-release: ## Build optimized release binary
	CGO_ENABLED=0 go build -ldflags "-s -w $(LDFLAGS)" -o bin/snapem ./cmd/snapem

install: ## Install to GOPATH/bin
	go install -ldflags "$(LDFLAGS)" ./cmd/snapem

## Development

run: build ## Build and run
	./bin/snapem $(ARGS)

fmt: ## Format code
	go fmt ./...

lint: ## Run linter
	golangci-lint run

vet: ## Run go vet
	go vet ./...

## Testing

test: ## Run tests
	go test -race -short ./...

test-verbose: ## Run tests with verbose output
	go test -race -v ./...

test-coverage: ## Run tests with coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Dependencies

deps: ## Download dependencies
	go mod download

tidy: ## Tidy dependencies
	go mod tidy

## Cleaning

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
