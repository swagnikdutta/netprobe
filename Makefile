BINARY_NAME=npctl
BINARY_PATH=/opt/homebrew/bin/

build:
	go build -o ${BINARY_PATH}${BINARY_NAME} github.com/swagnikdutta/netprobe/cmd #gosetup

run: build
	${BINARY_PATH}${BINARY_NAME} dig www.example.com

test_ping:
	${BINARY_PATH}${BINARY_NAME} test -count=1 ./pkg/ping

test:
	make test_ping
