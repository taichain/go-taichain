.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/taichain/go-taichain/cmd/swarm
	go build -o bin/geth     github.com/taichain/go-taichain/cmd/geth
	go build -o bin/bootnode github.com/taichain/go-taichain/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/taichain/go-taichain/swarm/...
