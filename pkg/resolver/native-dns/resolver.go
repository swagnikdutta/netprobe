package native_dns

import (
	"bytes"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg"
	"github.com/swagnikdutta/netprobe/pkg/dialer"
)

// Resolver is a native implementation of a dns resolver
type Resolver struct {
	// Nameserver will store the IP of a root nameserver.
	// There are 13 root nameserver IPs, which are hard-coded into
	// the resolver.
	//
	// In this implementation we will use the address of
	// a.root-servers.net name server i.e, 198.41.0.4
	Nameserver net.IP

	Dialer dialer.Dialer
}

func (r *Resolver) ResolveSource() (net.IP, error) {
	return nil, nil
}

func (r *Resolver) ResolveDestination(host string) (net.IP, error) {
	destIP, err := r.Resolve(host)
	if err != nil {
		return nil, err
	}

	_ = destIP
	return nil, nil
}

func (r *Resolver) Resolve(host string) (net.IP, error) {
	for true {
		reply, err := r.Query(host)
		if err != nil {
			return nil, errors.Wrapf(err, "error querying with host %s", host)
		}

		fmt.Println(reply)
		// ip = get_answer(reply)
		// if ip {
		// 	// done
		// }
		//
		// nameserverIP = get_glue(reply)
		// if nameseverIp {
		// 	// we get the ip address of the nameserver to ask next
		// 	r.Nameserver = nameseverip
		// } else {
		// 	// we get the domain name of the name server to ask next
		// 	return
		// }
		break
	}
	return nil, nil
}

func (r *Resolver) Query(host string) ([]byte, error) {
	message := NewDNSMessage(host)
	stream, err := message.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing resolver message")
	}

	pkg.PrintByteStream("dns message", stream)

	address := fmt.Sprintf("%s:%s", r.Nameserver.String(), "53")
	conn, err := r.Dialer.Dial("udp", address)
	if err != nil {
		return nil, errors.Wrapf(err, "Error dialing DNS server %s", r.Nameserver.String())
	}
	defer conn.Close()

	_, err = conn.Write(stream)
	if err != nil {
		return nil, errors.Wrapf(err, "error sending message on connection")
	}
	fmt.Printf("Sent resolver message with id: %v\n", message.Header.ID)

	reply := make([]byte, 2056)
	_, err = conn.Read(reply)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading reply")
	}
	reply = bytes.Trim(reply, "\x00")

	pkg.PrintByteStream("dns reply", reply)

	return reply, nil
}
