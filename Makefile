NAME := mcpurl
MAIN := ./cmd/$(NAME)
VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -s -w -X main.version=$(VERSION)

LINT_VERSION := v2.12.2

ifeq ($(RACE),1)
	GOFLAGS+=-race
endif

.PHONY: *

build:
	@CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(NAME) $(MAIN)

install:
	@CGO_ENABLED=0 go install -ldflags "$(LDFLAGS)" $(MAIN)

run:
	@go run $(GOFLAGS) $(MAIN) $(ARGS)

test:
	@go test -race ./...

fmt:
	@golangci-lint fmt

lint:
	@golangci-lint version
	@golangci-lint config verify
	@golangci-lint run

tools:
	@curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin $(LINT_VERSION)

version:
	@echo $(VERSION)

# Release binaries (05-plan.md M5): darwin arm64/amd64, linux amd64, windows amd64.
dist:
	@rm -rf dist && mkdir -p dist
	@GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(NAME)-darwin-arm64 $(MAIN)
	@GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(NAME)-darwin-amd64 $(MAIN)
	@GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(NAME)-linux-amd64 $(MAIN)
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(NAME)-windows-amd64.exe $(MAIN)
	@ls -lh dist/

clean:
	@rm -rf dist $(NAME)
