NAME=guest-portal
IMAGE=docker.w.jw4.us/$(NAME)

ifeq ($(ROOT_IMPORT_PATH),)
	ROOT_IMPORT_PATH="github.com/johnweldon/guest-portal"
endif

ifeq ($(CMD_REL_PATH),)
	CMD_REL_PATH="./cmd/portal"
endif

ifeq ($(BUILD_VERSION),)
	BUILD_VERSION=$(shell git describe --dirty --first-parent --always --tags)
endif

.PHONY: all
all: image

.PHONY: clean
clean:
	@-rm ./app ./portal
	go clean ./...

.PHONY: local
local:
	@go build \
			-ldflags="-s -w -X ${ROOT_IMPORT_PATH}.Version=${BUILD_VERSION}" \
			-tags netgo \
			-o app \
		${CMD_REL_PATH}

.PHONY: image
image:
	@docker build \
			--build-arg ROOT_IMPORT_PATH=$(ROOT_IMPORT_PATH) \
			--build-arg CMD_REL_PATH=$(CMD_REL_PATH) \
			--build-arg BUILD_VERSION=$(BUILD_VERSION) \
			-t $(IMAGE):latest \
			-t $(IMAGE):$(BUILD_VERSION) \
		.

.PHONY: push
push: clean image
	docker push $(IMAGE):$(BUILD_VERSION)
	docker push $(IMAGE):latest
