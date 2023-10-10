BINARY_NAME=netprobe

build:
	/usr/local/go/bin/go build -o /Users/swagnikdutta/go/netprobe/${BINARY_NAME} github.com/swagnikdutta/netprobe/cmd #gosetup

run: build
	./${BINARY_NAME} www.example.com
	make clean

clean:
	go clean
	rm ./${BINARY_NAME}

test_ping:
	/usr/local/go/bin/go test -count=1 ./pkg/ping

test:
	make test_ping
