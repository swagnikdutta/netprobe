package native_dns

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
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

	Meta struct {
		TxnIDMap map[uint16]interface{}
	}
}

func (r *Resolver) ResolveSource() (net.IP, error) {
	return nil, nil
}

func (r *Resolver) ResolveDestination(host string) (net.IP, error) {
	destIP, err := r.Resolve(host)
	if err != nil {
		return nil, err
	}

	return destIP, nil
}

func (r *Resolver) Resolve(host string) (net.IP, error) {
	for {
		reply, err := r.Query(host)
		if err != nil {
			return nil, errors.Wrapf(err, "error querying host %s", host)
		}

		m := NewDNSMessage()
		m.Deserialize(reply)

		if answer, has := m.hasAnswer(); has {
			if answer.Type == 1 {
				return net.ParseIP(answer.RDATA), nil
			}

			// handles CNAME records
			// if answer.Type == 5 {
			// 	nameserverDomain := answer.RDATA
			// 	ip, _ := r.Resolve(nameserverDomain)
			// 	r.Nameserver = ip
			// 	continue
			// }
		}

		if glueRecord, has := m.hasGlueRecord(); has {
			r.Nameserver = net.ParseIP(glueRecord.RDATA)
			continue
		}

		if nsRecord, has := m.hasNSRecord(); has {
			nameserverDomain := nsRecord.RDATA
			ip, _ := r.Resolve(nameserverDomain)
			r.Nameserver = ip
		}
	}

	return nil, nil
}

func (r *Resolver) Query(host string) ([]byte, error) {
	txnID := r.generateTxnID()
	message := NewDNSQuery(host, txnID)
	stream, err := message.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing resolver message")
	}

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

	// reply = bytes.Trim(reply, "\x00") // header id (16-bits) 00 83
	return reply, nil
}
