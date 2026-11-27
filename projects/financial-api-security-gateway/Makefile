.PHONY: all build test vet demo validate bench clean

BIN_DIR := bin

all: vet build test

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/gateway ./src/cmd/gateway
	go build -o $(BIN_DIR)/harness ./src/cmd/harness

vet:
	go vet ./...

test:
	go test -race -v ./...

demo: build
	./$(BIN_DIR)/gateway --demo --config-dir config --output-audit reports/audit_sample.jsonl

validate:
	./scripts/validate.sh

bench:
	./scripts/benchmark.sh

clean:
	rm -rf $(BIN_DIR)
