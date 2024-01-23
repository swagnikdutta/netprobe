BINARY_NAME=npctl

build:
	/usr/local/go/bin/go build -o /usr/local/go/bin/${BINARY_NAME} github.com/swagnikdutta/netprobe/cmd #gosetup

run: build
	/usr/local/go/bin/${BINARY_NAME} dig www.example.com

test_ping:
	/usr/local/go/bin/go test -count=1 ./pkg/ping

test:
	make test_ping
