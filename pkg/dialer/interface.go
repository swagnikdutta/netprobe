package dialer

import "net"

type NetworkDialer interface {
	Dial(network, address string) (net.Conn, error)
}
