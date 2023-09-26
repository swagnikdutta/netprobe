package ping

import "net"

type NetworkDialer interface {
	Dial(network, address string) (net.Conn, error)
}

type Dialer struct{}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
