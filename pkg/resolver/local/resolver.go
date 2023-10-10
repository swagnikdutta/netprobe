package local

import (
	"net"
)

type Resolver struct{}

func (r *Resolver) ResolveSource() (net.IP, error) {
	// The address does not need to exist as unlike tcp, udp does not require a handshake.
	// The goal here is to retrieve the outbound IP.
	// Source: https://stackoverflow.com/a/37382208/3728336
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sourceIP := conn.LocalAddr().(*net.UDPAddr).IP

	return sourceIP, nil
}

func (r *Resolver) ResolveDestination(dest string) (net.IP, error) {
	var destIP net.IP

	ips, err := net.LookupIP(dest)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			destIP = ipv4
		}
	}

	return destIP, nil
}
