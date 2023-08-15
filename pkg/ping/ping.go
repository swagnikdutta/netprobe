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

func (h *ICMPHeader) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, h.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Code); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Checksum); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Identifier); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.SequenceNumber); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (p *ICMPPacket) Serialize() ([]byte, error) {
	return p.Header.Serialize()
}

func (h *IPv4Header) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, h.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.IHL); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.TypeOfService); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.TotalLength); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Identification); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Flags); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.FragmentOffset); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.TTL); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Protocol); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Checksum); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.SourceIP); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.DestinationIP); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (p *IPv4Packet) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	payloadSerialized, err := p.Payload.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing ICMP packet")
	}

	buf.Write(payloadSerialized)

	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing IPv4 packet header")
	}

	buf.Write(headerSerialized)

	return buf.Bytes(), nil
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

func (pinger *Pinger) resolveAddress(dest string) error {
	ips, err := net.LookupIP(dest)
	if err != nil {
		return errors.Wrapf(err, "error resolving address of remote host")
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			pinger.destIP = ipv4
		}
	}

	// The destination address does not need to exist as unlike tcp, udp does not require a handshake.
	// The goal here is to retrieve the outbound IP. Source: https://stackoverflow.com/a/37382208/3728336
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return errors.Wrapf(err, "error resolving outbound ip address of local machine")
	}
	defer conn.Close()

	pinger.sourceIP = conn.LocalAddr().(*net.UDPAddr).IP

	return nil
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

	if err := pinger.resolveAddress(host); err != nil {
		return errors.Wrapf(err, "error resolving source/destination addresses")
	}

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
	pinger := new(Pinger)
	pinger.count = 3

	return pinger
}
