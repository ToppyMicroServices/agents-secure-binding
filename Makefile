BUILD_DIR = build
SERVICES = manager agent cli attestation-service log-forwarder computation-runner egress-proxy ingress-proxy
DIRECT_AGENT_CORE_PKGS = ./pkg/atls/... ./pkg/clients/... ./pkg/agtp/... ./pkg/production
PRODUCTION_CONSUMER_PKGS = ./examples/protected-change-consumer
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
EMBED_ENABLED ?= 0
INSTALL_DIR ?= /usr/local/bin
CONFIG_DIR ?= /etc/agents-secure-binding
SERVICE_NAME ?= agents-secure-binding-manager
SERVICE_DIR ?= /etc/systemd/system
SERVICE_FILE = init/systemd/$(SERVICE_NAME).service
IGVM_BUILD_SCRIPT := ./scripts/igvmmeasure/igvm.sh
GOVULNCHECK ?= go run golang.org/x/vuln/cmd/govulncheck@latest

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w" \
	$(if $(filter 1,$(EMBED_ENABLED)),-tags "embed",) \
	-o ${BUILD_DIR}/agents-secure-binding-$(1) ./cmd/$(1)
endef

.PHONY: all $(SERVICES) install clean product-security-gate fuzz-smoke

all: $(SERVICES)

$(SERVICES): 
	$(call compile_service,$@)
	@if [ "$@" = "cli" ] || [ "$@" = "manager" ]; then $(MAKE) build-igvm; fi

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative manager/manager.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/events/events.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/cvms/cvms.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/proto/attestation/v1/attestation.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/proto/attestation-agent/attestation-agent.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/log/log.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/runner/runner.proto

mocks:
	mockery --config ./.mockery.yml

install: $(SERVICES)
	install -d $(INSTALL_DIR)
	install $(BUILD_DIR)/agents-secure-binding-cli $(INSTALL_DIR)/agents-secure-binding-cli
	install $(BUILD_DIR)/agents-secure-binding-manager $(INSTALL_DIR)/agents-secure-binding-manager
	install -d $(CONFIG_DIR)
	install agents-secure-binding-manager.env $(CONFIG_DIR)/agents-secure-binding-manager.env

clean:
	rm -rf $(BUILD_DIR)

run: install_service
	sudo systemctl start $(SERVICE_NAME).service

stop:
	sudo systemctl stop $(SERVICE_NAME).service

install_service:
	sudo install -m 644 $(SERVICE_FILE) $(SERVICE_DIR)/$(SERVICE_NAME).service
	sudo systemctl daemon-reload

build-igvm:
	@echo "Running build script for igvmmeasure..."
	@$(IGVM_BUILD_SCRIPT)

product-security-gate:
	go mod verify
	GOTOOLCHAIN=go1.26.0+auto go test $(DIRECT_AGENT_CORE_PKGS)
	GOTOOLCHAIN=go1.26.0+auto go test -v -race -count=1 ./pkg/atls/identitypolicy ./pkg/clients ./pkg/production $(PRODUCTION_CONSUMER_PKGS)
	$(MAKE) fuzz-smoke
	$(GOVULNCHECK) ./...

fuzz-smoke:
	GOTOOLCHAIN=go1.26.0+auto go test -run '^$$' -fuzz=FuzzVerifySessionIdentityJWTRejectsMalformedCompactTokens -fuzztime=10s ./pkg/agtp
