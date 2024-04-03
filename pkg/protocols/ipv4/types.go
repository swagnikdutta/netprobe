package ipv4

import "net"

// Header represents the header of an IPv4 Packet.
// This struct defines the fields that make up the IPv4 packet header,
type Header struct {
	Version       uint8
	IHL           uint8
	TypeOfService uint8
	// Total Length is the length of the datagram, measured in octets, including internet header and data
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	// In IPv4, checksum is calculated only on the header
	Checksum      uint16
	SourceIP      net.IP
	DestinationIP net.IP
}

// Packet represents an IPv4 packet.
type Packet struct {
	Header  *Header
	Payload []byte
}
