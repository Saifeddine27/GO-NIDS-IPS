.PHONY: build run setup clean test

setup:
	go mod tidy

build: setup
	go build -o bin/nids ./cmd/nids

run: build
	sudo ./bin/nids

clean:
	rm -rf ./bin

test:
	go test -v ./internal/engine

