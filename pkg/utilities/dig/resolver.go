package dig

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/swagnikdutta/netprobe/pkg/dialer"
)

// Resolver is a native implementation of a dns resolver
type Resolver struct {
	// RootNameserver stores the IP address of the root nameserver.
	// There are 13 root nameservers in total, all of which are hardcoded in a resolver.
	RootNameserver net.IP

	Dialer dialer.Dialer
	Logger *Logger
	Meta   struct {
		TxnIDMap map[uint16]interface{}
	}
}

func NewResolver(v bool) *Resolver {
	r := new(Resolver)
	r.RootNameserver = getNameserverIP()
	r.Logger = &Logger{Verbose: v}
	r.Meta.TxnIDMap = make(map[uint16]interface{})
	return r
}

func (r *Resolver) ResolveSource() (net.IP, error) {
	// The address does not need to exist as unlike tcp, udp does not require a handshake.
	// The goal here is to retrieve the outbound IP.
	// Source: https://stackoverflow.com/a/37382208/3728336
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, errors.Wrapf(err, "error resolving outbound ip address")
	}
	defer conn.Close()

	sourceIP := conn.LocalAddr().(*net.UDPAddr).IP
	return sourceIP, nil
}

func (r *Resolver) ResolveDestination(host string) (net.IP, error) {
	destIP, err := r.Resolve(host)
	if err != nil {
		return nil, err
	}

	return destIP, nil
}

func (r *Resolver) Resolve(host string) (net.IP, error) {
	nameserver := r.RootNameserver.String()

	for {
		reply, err := r.Query(host, nameserver)
		if err != nil {
			return nil, errors.Wrapf(err, "error querying host %s", host)
		}

		m := NewDNSMessage()
		m.Deserialize(reply)

		if answer, has := m.hasAnswer(); has {
			if answer.Type == 1 {
				r.Logger.logV("Answer record (type A) found\nnameserver:\t\t\t%s\naddress:\t\t\t%s\n\n", answer.Name, answer.RDATA)
				return net.ParseIP(answer.RDATA), nil
			}

			// handles CNAME records
			if answer.Type == 5 {
				r.Logger.logV("Answer record (type CNAME) found\nnameserver:\t\t\t%s\naddress:\t\t\t%s\n\n", answer.Name, answer.RDATA)
				nameserverDomain := answer.RDATA
				return r.Resolve(nameserverDomain)
			}
		}

		if glueRecord, has := m.hasGlueRecord(); has {
			nameserver = glueRecord.RDATA
			r.Logger.logV("Glue record found\nnameserver:\t\t\t%s\naddress:\t\t\t%s\n\n", glueRecord.Name, glueRecord.RDATA)
			continue
		}

		if nsRecord, has := m.hasNSRecord(); has {
			nameserverDomain := nsRecord.RDATA
			r.Logger.logV("NS record found\nnameserver:\t\t\t%s\n\n", nsRecord.RDATA)

			ip, err := r.Resolve(nameserverDomain)
			if err != nil {
				return nil, errors.Wrapf(err, "error resolving domain: %s", nameserverDomain)
			}

			nameserver = ip.String()
			continue
		}

		return nil, errors.Errorf("Failed to resolve address of host: %s\n", host)
	}
}

func (r *Resolver) Query(host, nameserver string) ([]byte, error) {
	r.Logger.logV("Querying nameserver %s for host: %s\n\n", nameserver, host)
	txnID := r.generateTxnID()
	message := NewDNSQuery(host, txnID)
	stream, err := message.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing resolver message")
	}

	address := fmt.Sprintf("%s:%s", nameserver, "53")
	conn, err := r.Dialer.Dial("udp", address)
	if err != nil {
		return nil, errors.Wrapf(err, "Error dialing DNS server %s", nameserver)
	}
	defer conn.Close()

	_, err = conn.Write(stream)
	if err != nil {
		return nil, errors.Wrapf(err, "error sending message on connection")
	}

	reply := make([]byte, 2056)
	_, err = conn.Read(reply)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading reply")
	}

	return reply, nil
}

func NewDigCommand() *cobra.Command {
	digCmd := &cobra.Command{
		Use:   "dig example.com",
		Short: "resolve IP address of host",
		Long:  "\nThe dig command uses the native resolver to resolve IP address of host",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			host := args[0]

			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				cmd.PrintErrln(err)
			}

			r := NewResolver(verbose)
			ip, _ := r.Resolve(host)
			r.Logger.log("IP address of %s is: %s\n", host, ip.String())
		},
	}
	digCmd.Flags().BoolP("verbose", "v", false, "enable verbose mode to display detailed logs")

	return digCmd
}
