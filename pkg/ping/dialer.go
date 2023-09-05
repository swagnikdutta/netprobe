package ping

import (
	"net"
)

type NetworkDialer interface {
	Dial(network, address string) (net.Conn, error)
}

type UDPDialer struct{}

func (d *UDPDialer) Dial(network, address string) (net.Conn, error) {
	// The destination address does not need to exist as unlike tcp, udp does not require a handshake.
	// The goal here is to retrieve the outbound IP.
	// Source: https://stackoverflow.com/a/37382208/3728336
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
