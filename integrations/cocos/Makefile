BUILD_DIR ?= build
CGO_ENABLED ?= 0
GO ?= go

.PHONY: all agent cli hardware-attestation-redteam test

all: agent cli hardware-attestation-redteam

agent:
	mkdir -p $(BUILD_DIR)
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) $(GO) build \
		-o $(BUILD_DIR)/agents-secure-binding-agent ./cmd/agent

cli:
	mkdir -p $(BUILD_DIR)
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) $(GO) build \
		-o $(BUILD_DIR)/agents-secure-binding-cli ./cmd/cli

hardware-attestation-redteam:
	mkdir -p $(BUILD_DIR)
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) $(GO) build \
		-o $(BUILD_DIR)/hardware-attestation-redteam \
		./cmd/hardware-attestation-redteam

test:
	GOWORK=off $(GO) mod tidy -diff
	GOWORK=off $(GO) mod verify
	GOWORK=off $(GO) test -race -count=1 ./...
	GOWORK=off $(GO) vet ./...
