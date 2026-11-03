BINARY  := intrasec
PKG     := github.com/Sangmoo/intrasec
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

export CGO_ENABLED := 0

.PHONY: all deps test test-integration test-race lint vuln secrets web build run-lab stop-lab clean

all: lint test build

deps:
	go mod download
	@if [ -f web/package.json ]; then cd web && npm ci; fi

test:
	go test -count=1 ./...

test-integration:
	go test -tags integration -count=1 -v ./internal/integration/

test-race:
	CGO_ENABLED=1 go test -race -count=1 ./...

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

secrets:
	gitleaks detect --source . --no-banner

web:
	@if [ -f web/package.json ]; then cd web && npm run build; else echo "web: 프론트엔드 미구현 (M3), 건너뜀"; fi

build: web
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/intrasec

run-lab:
	docker compose -f deploy/docker-compose.yml up -d

stop-lab:
	docker compose -f deploy/docker-compose.yml down

clean:
	rm -rf bin dist coverage.out
