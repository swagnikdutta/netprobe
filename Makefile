BINARY_NAME=npctl
#BINARY_LOCATION=/usr/local/go/bin
BINARY_LOCATION=/Users/swagnikdutta/go/netprobe

build:
	/usr/local/go/bin/go build -o ${BINARY_LOCATION}/${BINARY_NAME} github.com/swagnikdutta/netprobe/cmd #gosetup

run: build
	${BINARY_LOCATION}/${BINARY_NAME} dig example.com

test_ping:
	/usr/local/go/bin/go test -count=1 ./pkg/ping

test:
	make test_ping
