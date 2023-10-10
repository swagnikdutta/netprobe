package resolver

import "net"

type Resolver interface {
	ResolveSource() (net.IP, error)
	ResolveDestination(dest string) (net.IP, error)
}
