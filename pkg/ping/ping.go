package ping

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/pkg/errors"
)

var (
	IcmpProtocolNumber uint8 = 1
	IPv4Version        uint8 = 4
	IPv4IHL            uint8 = 5
	ICMPHeaderType     uint8 = 8
	ICMPHeaderSubtype  uint8 = 0
)

type Pinger struct {
	sourceIP net.IP
	destIP   net.IP
	count    uint8
	resolver AddressResolver
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

	// pinger.printSerializedData(packetSerialized, "IP payload/ICMP packet")
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

	// pinger.printSerializedData(packetHeaderSerialized, "IP header")
	ipPacket.Header.Checksum = calculateChecksum(packetHeaderSerialized)

	return ipPacket, nil
}

func (pinger *Pinger) parseEchoReply(echoReply []byte, echoRequest *IPv4Packet) {
	icmpOffset := 20
	icmpHeaderSize := 8
	icmpHeaderBytes := echoReply[icmpOffset : icmpOffset+icmpHeaderSize]

	seqNoOffset := 6
	seqNo := binary.BigEndian.Uint16(icmpHeaderBytes[seqNoOffset:])
	fmt.Printf("received ICMP echo packet from %v, seq no: %v\n\n", echoRequest.Header.SourceIP, seqNo)
}

func (pinger *Pinger) Ping(host string) error {
	log.Printf("Performing ping tests...\n\n")

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

	for i := 0; i < int(pinger.count); i++ {
		packet, err := pinger.createIPv4Packet(i)
		if err != nil {
			return errors.Wrapf(err, "error creating IPv4 packet")
		}

		packetSerialized, err := packet.Serialize()
		if err != nil {
			return errors.Wrapf(err, "error serializing IPv4 packet")
		}
		// pinger.printSerializedData(packetSerialized, "echo request ip packet(payload|header)")

		conn, err := net.Dial("ip4:icmp", packet.Header.DestinationIP.String())
		if err != nil {
			return errors.Wrapf(err, "error eshtablishing connection with %s", host)
		}
		defer conn.Close()

		_, err = conn.Write(packetSerialized)
		if err != nil {
			return errors.Wrapf(err, "error sending ICMP echo request")
		}
		fmt.Printf("sending ICMP echo request (%v bytes) from %v, seq_no: %v\n", packet.Header.TotalLength, packet.Header.SourceIP, packet.Payload.Header.SequenceNumber)

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
		count:    3,
		resolver: new(LocalResolver),
	}

	return pinger
}
