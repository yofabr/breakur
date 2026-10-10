.DEFAULT_GOAL := help

BINARY := bin/breakur

.PHONY: help run build test vet fmt tidy up down restart logs ps clean db

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

run: ## run the API locally (no docker)
	go run ./cmd

build: ## build release binary into bin/
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd

test: ## run tests
	go test ./...

vet: ## run go vet
	go vet ./...

fmt: ## format sources
	go fmt ./...

tidy: ## sync go.mod / go.sum
	go mod tidy

db: ## start only the postgres database (host-accessible on localhost:5432)
	docker compose up -d --wait postgres

up: ## start app + postgres + redis
	docker compose up --build -d

down: ## stop containers (keeps volumes)
	docker compose down

restart: ## rebuild and restart the app only
	docker compose up --build -d --force-recreate app

logs: ## tail app logs
	docker compose logs -f app

ps: ## show container status
	docker compose ps

clean: ## remove build artifacts
	rm -rf bin
