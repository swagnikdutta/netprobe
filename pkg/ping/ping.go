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
	"github.com/swagnikdutta/netprobe/pkg/resolver"
	"github.com/swagnikdutta/netprobe/pkg/resolver/local"
	native_dns "github.com/swagnikdutta/netprobe/pkg/resolver/native-dns"
)

var (
	IcmpProtocolNumber uint8 = 1
	IPv4Version        uint8 = 4
	IPv4IHL            uint8 = 5
	ICMPHeaderType     uint8 = 8
	ICMPHeaderSubtype  uint8 = 0

	resolverType string
	pingCount    int
)

type Pinger struct {
	sourceIP net.IP
	destIP   net.IP
	count    uint8
	resolver resolver.Resolver
	dialer   dialer.NetworkDialer
}

func (pinger *Pinger) createICMPPacket(seqNo int) (*ICMPPacket, error) {
	packet := &ICMPPacket{
		Header: &ICMPHeader{
			Type:           ICMPHeaderType,
			Code:           ICMPHeaderSubtype,
			Checksum:       0,
			Identifier:     0,
			SequenceNumber: uint16(seqNo),
		},
	}

	packetSerialized, err := packet.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing ICMP packet")
	}

	packet.Header.Checksum = calculateChecksum(packetSerialized)

	return packet, nil
}

func (pinger *Pinger) createIPv4Packet(count int) (*IPv4Packet, error) {
	ipPacket := &IPv4Packet{
		Header: &IPv4Header{
			Version:       IPv4Version,
			IHL:           IPv4IHL,
			TTL:           64,
			Protocol:      IcmpProtocolNumber,
			SourceIP:      pinger.sourceIP,
			DestinationIP: pinger.destIP,
		},
	}

	icmpPacket, err := pinger.createICMPPacket(count)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating ICMP packet")
	}

	ipPacket.Payload = icmpPacket
	ipPacket.Header.TotalLength = 50

	packetHeaderSerialized, err := ipPacket.Header.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing IPv4 packet header")
	}

	ipPacket.Header.Checksum = calculateChecksum(packetHeaderSerialized)

	return ipPacket, nil
}

func (pinger *Pinger) parseEchoReply(echoReply []byte, echoRequest *IPv4Packet) {
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

	fmt.Printf("Host IP address resolved. Performing ping tests...\n\n")

	for i := 0; i < int(pinger.count); i++ {
		packet, err := pinger.createIPv4Packet(i)
		if err != nil {
			return errors.Wrapf(err, "error creating IPv4 packet")
		}

		packetSerialized, err := packet.Serialize()
		if err != nil {
			return errors.Wrapf(err, "error serializing IPv4 packet")
		}

		conn, err := pinger.dialer.Dial("ip4:icmp", packet.Header.DestinationIP.String())
		if err != nil {
			return errors.Wrapf(err, "error eshtablishing connection with %s", host)
		}
		defer conn.Close()

		_, err = conn.Write(packetSerialized)
		if err != nil {
			return errors.Wrapf(err, "error sending ICMP echo request")
		}
		fmt.Printf("sending ICMP echo request (%v bytes) from %v, to %v, seq_no: %v\n", packet.Header.TotalLength,
			packet.Header.SourceIP, packet.Header.DestinationIP, packet.Payload.Header.SequenceNumber)

		echoReply := make([]byte, 2048)
		_, err = conn.Read(echoReply)
		if err != nil {
			return errors.Wrapf(err, "error receiving ICMP echo response")
		}

		echoReply = bytes.Trim(echoReply, "\x00")
		pinger.parseEchoReply(echoReply, packet)
	}

	log.Println("Ping tests completed.")
	return nil
}

func NewPinger() *Pinger {
	pinger := &Pinger{
		count:  uint8(pingCount),
		dialer: new(dialer.Dialer),
	}

	switch resolverType {
	case "native":
		r := new(native_dns.Resolver)
		r.Meta.TxnIDMap = make(map[uint16]interface{})
		r.RootNameServer = net.IP{198, 41, 0, 4}

		pinger.resolver = r
	case "local":
		pinger.resolver = new(local.Resolver)
	}

	return pinger
}

func NewPingCommand() *cobra.Command {
	pingCmd := &cobra.Command{
		Use:   "ping example.com",
		Short: "send ICMP ECHO_REQUEST packets to network host",
		Long:  "The ping utility is used to test connection with a host by sending ICMP echo request packets",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			host := args[0]
			pinger := NewPinger()

			if err := pinger.Ping(host); err != nil {
				log.Printf("error pinging host: %v", err)
			}
		},
	}

	pingCmd.Flags().IntVarP(&pingCount, "count", "c", 3, "specify number of packets to send")
	pingCmd.Flags().StringVarP(&resolverType, "resolver", "r", "native",
		`dns resolver to use, choices are "native" or "local"`)

	return pingCmd
}
