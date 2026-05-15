BINARY  := mfa-app
IMAGE   := ghcr.io/natanrigailo/mfa-app

.PHONY: run build lint test up down clean

run: ## Build and run locally (requires Go)
	go run .

build: ## Build binary
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) .

lint: ## Run golangci-lint (requires golangci-lint installed)
	golangci-lint run ./...

test: ## Run tests
	go test -v -race ./...

up: ## Build Docker image and start via Compose
	docker compose up -d --build

down: ## Stop Compose stack
	docker compose down

clean: ## Remove binary and Docker image
	rm -f $(BINARY)
	docker rmi $(IMAGE) 2>/dev/null || true

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
