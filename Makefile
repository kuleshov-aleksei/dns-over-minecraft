BINARY      := dnsmc
CMD         := ./cmd/dnsmc
CONFIG      ?= config.yaml
CLIENT_CONFIG ?= config.client.yaml
LISTEN      ?= :25565
CLIENT_LISTEN ?=          # local DNS listen addr for client-service (empty -> config client.listen)
SERVER      ?= 127.0.0.1:25565
SUFFIX      ?= .mc
NAME        ?= mybox.mc
TYPE        ?= A

GOFLAGS     :=
CLIENT_LISTEN_ARGS = $(if $(CLIENT_LISTEN),-listen $(CLIENT_LISTEN),)

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: help build run-server server query client client-service load vet test clean docker docker-run

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build binary to ./$(BINARY)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

vet: ## Run go vet
	go vet ./...

test: ## Run tests (vet + build check)
	go vet ./...
	go test ./... 2>&1 | head -n 50

run-server: build ## Run server (CONFIG, LISTEN, SUFFIX overridable)
	@if [ ! -f "$(CONFIG)" ] && [ -f "config.yaml.example" ]; then echo "=> $(CONFIG) not found, using config.yaml.example"; cp config.yaml.example $(CONFIG); fi
	./$(BINARY) -S -config $(CONFIG) -listen $(LISTEN) -suffix $(SUFFIX)

server: run-server ## Alias for run-server

query: build ## Query via MC ping: make query NAME=example.com TYPE=A SERVER=127.0.0.1:25565
	./$(BINARY) -config $(CLIENT_CONFIG) -server $(SERVER) -suffix $(SUFFIX) $(NAME) $(TYPE)

client: query ## Alias for query

# Run the client as a local DNS service (UDP+TCP). CLIENT_LISTEN overridable.
client-service: build ## Run local DNS client service
	@if [ ! -f "$(CLIENT_CONFIG)" ] && [ -f "config.client.yaml.example" ]; then echo "=> $(CLIENT_CONFIG) not found, using config.client.yaml.example"; cp config.client.yaml.example $(CLIENT_CONFIG); fi
	./$(BINARY) -C -config $(CLIENT_CONFIG) $(CLIENT_LISTEN_ARGS) -suffix $(SUFFIX)

# Example: make query-custom NAME=hello.mc TYPE=TXT
query-custom: query

# Generate light DNS load (dig) against a running client service (RESOLVER, PORT, QUERIES, DELAY overridable)
load: ## Send test queries via dig to a running client service (assumes server + client-service running)
	./scripts/load.sh

# Quick demo: start server in background, query custom records, stop
demo: build ## Run server, query mybox.mc/hello.mc/foo.internal.mc, stop
	@if [ ! -f "$(CONFIG)" ]; then cp config.yaml.example $(CONFIG); fi
	@./$(BINARY) -S -config $(CONFIG) -listen $(LISTEN) & echo $$! > /tmp/dnsmc.pid; \
	sleep 0.5; \
	echo "=> query $(NAME) $(TYPE) @ $(SERVER)"; \
	./$(BINARY) -config $(CONFIG) -server $(SERVER) -suffix $(SUFFIX) mybox.mc A || true; \
	./$(BINARY) -config $(CONFIG) -server $(SERVER) -suffix $(SUFFIX) hello.mc TXT || true; \
	./$(BINARY) -config $(CONFIG) -server $(SERVER) -suffix $(SUFFIX) foo.internal.mc A || true; \
	kill `cat /tmp/dnsmc.pid` 2>/dev/null || true; wait `cat /tmp/dnsmc.pid` 2>/dev/null || true; rm -f /tmp/dnsmc.pid; \
	echo "=> demo done"

clean: ## Remove binary
	rm -f $(BINARY) /tmp/dnsmc

docker: ## Build docker image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t dnsmc .

docker-run: ## Run docker image (LISTEN, CONFIG)
	docker run --rm -p 25565:25565 -v $(PWD)/$(CONFIG):/config.yaml dnsmc -S -config /config.yaml -listen $(LISTEN)
