TEST         ?= ./...
TESTARGS     ?=
TEST_COUNT   ?= 1
TEST_TIMEOUT ?= 20m

BINARY       = terraform-provider-unifi
VERSION      = 99.0.0
PLUGIN_DIR   = registry.terraform.io/filipowm/unifi/$(VERSION)

LOCAL_OS     = $(shell go env GOOS)
LOCAL_ARCH   = $(shell go env GOARCH)
LOCAL_PLATFORM = $(LOCAL_OS)_$(LOCAL_ARCH)

DEPLOY_HOST  ?=
TF_DIR       ?=

.PHONY: default
default: build

# Build for the local platform
.PHONY: build
build:
	go build -o $(BINARY) .

# Build and install into local Terraform plugin directory
.PHONY: install
install: build
	mkdir -p ~/.terraform.d/plugins/$(PLUGIN_DIR)/$(LOCAL_PLATFORM)
	cp $(BINARY) ~/.terraform.d/plugins/$(PLUGIN_DIR)/$(LOCAL_PLATFORM)/$(BINARY)

# Cross-compile for Linux ARM64 (UDM-SE, docker-host, etc.)
.PHONY: build-linux-arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)_linux_arm64 .

# Cross-compile for Linux AMD64
.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)_linux_amd64 .

# Deploy to a remote host via scp
# Usage: make deploy DEPLOY_HOST=root@192.168.1.1
#        make deploy DEPLOY_HOST=root@192.168.1.1 TF_DIR=/root/terraform
.PHONY: deploy
deploy: build-linux-arm64
	@if [ -z "$(DEPLOY_HOST)" ]; then echo "Error: set DEPLOY_HOST (e.g. make deploy DEPLOY_HOST=root@192.168.1.1)"; exit 1; fi
	ssh $(DEPLOY_HOST) 'mkdir -p ~/.terraform.d/plugins/$(PLUGIN_DIR)/linux_arm64'
	scp $(BINARY)_linux_arm64 $(DEPLOY_HOST):~/.terraform.d/plugins/$(PLUGIN_DIR)/linux_arm64/$(BINARY)
	@if [ -n "$(TF_DIR)" ]; then \
		echo "Reinitializing Terraform on $(DEPLOY_HOST)..."; \
		ssh $(DEPLOY_HOST) 'cd $(TF_DIR) && rm -f .terraform.lock.hcl && terraform init'; \
	fi

.PHONY: testacc
testacc:
	go build ./...
	TF_ACC=1 go test $(TEST) -v -count $(TEST_COUNT) -timeout $(TEST_TIMEOUT) $(TESTARGS)

.PHONY: clean
clean:
	rm -f $(BINARY) $(BINARY)_linux_arm64 $(BINARY)_linux_amd64
