MODULE := $(shell head -1 go.mod | awk '{print $$2}')
BINARY := raven
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
  -X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
  -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
  -X $(MODULE)/internal/buildinfo.Date=$(DATE)

.PHONY: build build-linux run test lint check fuzz proto clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/raven

# Static linux/amd64 binary for deployment hosts, from any build machine.
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./cmd/raven

run: build
	./$(BINARY) serve --config raven.yaml

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

check: lint
	go test ./...

# Fuzz the BMP/BGP decoders, each target for FUZZTIME (default 5m). Not part
# of check or CI. Failing inputs land in internal/bmp/testdata/fuzz/ and are
# replayed by every go test from then on.
FUZZTIME ?= 5m
FUZZ_TARGETS := FuzzBMPMessage FuzzPeerUpOpen FuzzDecodeUpdate

fuzz:
	@for t in $(FUZZ_TARGETS); do 		echo "== $$t ($(FUZZTIME))"; 		go test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) ./internal/bmp/ || exit 1; 	done

proto:
	buf generate

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64
	rm -rf dist/
