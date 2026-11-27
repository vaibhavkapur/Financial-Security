.PHONY: build test test-race bench demo validate reports clean

GOCACHE ?= /tmp/tism-gocache
BIN := bin/tism

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -o $(BIN) ./src/cmd/tism

test:
	GOCACHE=$(GOCACHE) go test -v ./...

test-race:
	GOCACHE=$(GOCACHE) go test -race -count=1 ./...

bench:
	GOCACHE=$(GOCACHE) go test -run=^$$ -bench=. -benchmem ./tests/...

demo:
	./scripts/run_demo.sh

validate:
	./scripts/validate.sh

reports:
	./scripts/generate_reports.sh

clean:
	rm -rf bin /tmp/tism-gocache
