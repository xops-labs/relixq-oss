MODULE  = github.com/relix-q/relix-q/cmd/relixq
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS  = -s -w -X '$(MODULE)/cmd.Version=$(VERSION)' -X '$(MODULE)/cmd.Commit=$(COMMIT)'
OUT      = dist

.PHONY: build build-all test lint clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(OUT)/relixq .

build-all: clean
	GOOS=linux   GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o $(OUT)/relixq_linux_amd64   .
	GOOS=linux   GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o $(OUT)/relixq_linux_arm64   .
	GOOS=darwin  GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o $(OUT)/relixq_darwin_amd64  .
	GOOS=darwin  GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o $(OUT)/relixq_darwin_arm64  .
	GOOS=windows GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o $(OUT)/relixq_windows_amd64.exe .

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(OUT)
