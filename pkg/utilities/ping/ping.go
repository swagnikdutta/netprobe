package ping

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/swagnikdutta/netprobe/pkg/dialer"
	"github.com/swagnikdutta/netprobe/pkg/protocols/icmp"
	"github.com/swagnikdutta/netprobe/pkg/protocols/ipv4"
	"github.com/swagnikdutta/netprobe/pkg/utilities/dig"
)

var (
	HeaderType         uint8 = 8
	HeaderSubtype      uint8 = 0
	ICMPProtocolNumber uint8 = 1
	Version            uint8 = 4
	IHL                uint8 = 5
)

type Pinger struct {
	sourceIP net.IP
	destIP   net.IP
	count    uint8
	resolver *dig.Resolver
	dialer   dialer.NetworkDialer
}

func (pinger *Pinger) parseEchoReply(echoReply []byte, echoRequest *ipv4.Packet) {
	// echoReply represents a serialized IP packet where the initial 20 bytes constitute the IP header (hence icmpOffset: 20).
	// Following the IP header are the bytes representing the IP payload, which, in this case, is the ICMP packet.
	icmpOffset := 20
	icmpHeaderSize := 8
	icmpHeaderBytes := echoReply[icmpOffset : icmpOffset+icmpHeaderSize]

	seqNoOffset := 6
	seqNo := binary.BigEndian.Uint16(icmpHeaderBytes[seqNoOffset:])
	fmt.Printf("received ICMP echo packet from %v, seq no: %v\n\n", echoRequest.Header.DestinationIP, seqNo)
}

func (pinger *Pinger) Ping(host string) error {
	ip, err := pinger.resolver.ResolveSource()
	if err != nil {
		return errors.Wrapf(err, "error resolving source address")
	}
	pinger.sourceIP = ip

	ip, err = pinger.resolver.ResolveDestination(host)
	if err != nil {
		return errors.Wrapf(err, "error resolving destination address")
	}
	pinger.destIP = ip

	fmt.Printf("\nAddress resolution complete\nHost address: \t\t%v\nDestination address: \t%v\n\nPerforming ping tests...\n\n", pinger.sourceIP, pinger.destIP)

	for i := 0; i < int(pinger.count); i++ {
		icmpHeader := icmp.Header{
			Type:           HeaderType,
			Code:           HeaderSubtype,
			SequenceNumber: uint16(i),
		}
		icmpPacket, icmpPacketSerialized, err := icmp.CreatePacket(icmpHeader)
		if err != nil {
			return errors.Wrapf(err, "error creating ICMP packet")
		}

		ipHeader := ipv4.Header{
			Version:       Version,
			IHL:           IHL,
			TTL:           64,
			Protocol:      ICMPProtocolNumber,
			SourceIP:      pinger.sourceIP,
			DestinationIP: pinger.destIP,
		}
		ipPacket, ipPacketSerialized, err := ipv4.CreatePacket(ipHeader, icmpPacketSerialized)
		if err != nil {
			return errors.Wrapf(err, "error creating IPv4 packet")
		}

		conn, err := pinger.dialer.Dial("ip4:icmp", pinger.destIP.String())
		if err != nil {
			return errors.Wrapf(err, "error eshtablishing connection with %s", host)
		}
		defer conn.Close()

		_, err = conn.Write(ipPacketSerialized)
		if err != nil {
			return errors.Wrapf(err, "error sending ICMP echo request")
		}

		fmt.Printf("sent ICMP echo request (%v bytes) from %v, to %v, seq_no: %v\n", ipPacket.Header.TotalLength,
			ipPacket.Header.SourceIP, ipPacket.Header.DestinationIP, icmpPacket.Header.SequenceNumber)

		echoReply := make([]byte, 2048)
		_, err = conn.Read(echoReply)
		if err != nil {
			return errors.Wrapf(err, "error receiving ICMP echo response")
		}

		echoReply = bytes.Trim(echoReply, "\x00")
		pinger.parseEchoReply(echoReply, ipPacket)
	}

	fmt.Println("Ping tests completed.")
	return nil
}

func NewPinger(count int, verbose bool) *Pinger {
	pinger := &Pinger{
		count:  uint8(count),
		dialer: new(dialer.Dialer),
	}
	pinger.resolver = dig.NewResolver(verbose)
	return pinger
}

func NewPingCommand() *cobra.Command {
	pingCmd := &cobra.Command{
		Use:   "ping example.com",
		Short: "send ICMP ECHO_REQUEST packets to network host",
		Long:  "\nThe ping utility is used to test connection with a host by sending ICMP echo request packets",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			host := args[0]

			count, err := cmd.Flags().GetInt("count")
			if err != nil {
				cmd.PrintErrln(err)
			}

			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				cmd.PrintErrln(err)
			}

			pinger := NewPinger(count, verbose)
			if err := pinger.Ping(host); err != nil {
				log.Printf("error pinging host: %v", err)
			}
		},
	}
	pingCmd.Flags().IntP("count", "c", 3, "specify number of packets to send")
	pingCmd.Flags().BoolP("verbose", "v", false, "enable verbose mode to display detailed logs")

	return pingCmd
}
