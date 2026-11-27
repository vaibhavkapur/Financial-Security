.PHONY: all build test test-race vet demo reports bench validate clean

GO ?= go
BIN_DIR := bin
CUSTODY_BIN := $(BIN_DIR)/custody

all: validate

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(CUSTODY_BIN) ./src/cmd/custody

vet:
	$(GO) vet ./...

test:
	$(GO) test -v ./...

test-race:
	$(GO) test -race -count=1 ./...

bench:
	$(GO) test -bench=. -benchmem ./tests/...

demo: build
	./scripts/run_demo.sh

reports: build
	./scripts/generate_reports.sh

validate:
	./scripts/validate.sh

clean:
	rm -rf $(BIN_DIR)
