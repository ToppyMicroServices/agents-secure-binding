BUILD_DIR = build
SERVICES = manager cli attestation-service log-forwarder computation-runner egress-proxy
DIRECT_AGENT_CORE_PKGS = ./pkg/atls/... ./pkg/clients/... ./pkg/agtp/... ./pkg/production
ASB_CORE_PKGS = ./pkg/atls/... ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc ./pkg/agtp/... ./pkg/tls
PRODUCTION_CONSUMER_PKGS = ./examples/protected-change-consumer
CGO_ENABLED ?= 0
GOARCH ?= amd64
A2A_GOOS ?= $(shell go env GOOS)
A2A_GOARCH ?= $(shell go env GOARCH)
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
A2A_VERSION ?= $(shell git describe --tags --always --dirty)
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

.PHONY: all $(SERVICES) a2a-test mac-debug-a2a install install-a2a-test clean product-security-gate fuzz-smoke \
	test-asb-core test-attestation-modules check-asb-core-boundary \
	check-attestation-v2-boundary check-attestation-v2-release \
	check-attestation-release check-cocos-release

all: $(SERVICES)

$(SERVICES): 
	$(call compile_service,$@)
	@if [ "$@" = "cli" ] || [ "$@" = "manager" ]; then $(MAKE) build-igvm; fi

a2a-test:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(A2A_GOOS) GOARCH=$(A2A_GOARCH) \
	go build -ldflags "-s -w -X main.version=$(A2A_VERSION) -X main.commit=$(COMMIT)" \
	-o $(BUILD_DIR)/asb-a2a-test ./examples/a2a-multiprocess

mac-debug-a2a: a2a-test
	./$(BUILD_DIR)/asb-a2a-test --debug-simple

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

install-a2a-test: a2a-test
	install -d $(INSTALL_DIR)
	install $(BUILD_DIR)/asb-a2a-test $(INSTALL_DIR)/asb-a2a-test

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
	GOTOOLCHAIN=go1.26.6+auto go test $(DIRECT_AGENT_CORE_PKGS)
	GOTOOLCHAIN=go1.26.6+auto go test -v -race -count=1 ./pkg/atls/identitypolicy ./pkg/clients ./pkg/production ./cmd/redis-failover-redteam $(PRODUCTION_CONSUMER_PKGS)
	$(MAKE) fuzz-smoke
	$(GOVULNCHECK) ./...

fuzz-smoke:
	GOTOOLCHAIN=go1.26.6+auto go test -run '^$$' -fuzz=FuzzVerifySessionIdentityJWTRejectsMalformedCompactTokens -fuzztime=10s ./pkg/agtp

check-asb-core-boundary:
	sh ./scripts/check-asb-core-boundary.sh

check-attestation-v2-boundary:
	sh ./scripts/check-attestation-v2-boundary.sh

check-attestation-v2-release:
	sh ./scripts/check-attestation-v2-release.sh

check-attestation-release:
	sh ./scripts/check-attestation-release.sh

check-cocos-release:
	sh ./scripts/check-cocos-release.sh

test-asb-core: check-asb-core-boundary
	GOWORK=off go test $(ASB_CORE_PKGS)

test-attestation-modules:
	GOWORK=off go test ./pkg/attestation/...
	cd modules/attestation/snp && GOWORK=off go test ./...
	cd modules/attestation/tdx && GOWORK=off go test ./...
	cd integrations/cocos && GOWORK=off go test ./...
