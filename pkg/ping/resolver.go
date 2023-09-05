package ping

import (
	"net"
)

type AddressResolver interface {
	LookupIP(host string) ([]net.IP, error)
}

type LocalResolver struct{}

func (r *LocalResolver) LookupIP(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	return ips, nil
}
