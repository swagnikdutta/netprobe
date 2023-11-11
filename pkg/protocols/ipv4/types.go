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
	// Protocol specifies the protocol used in the encapsulated segment(payload) of the packet. It tells the receiving
	// system how to interpret and process the packet data. For example, 6 indicates that the encapsulated segment is a
	// TCP segment. Likewise, 1 for ICMP, 17 for UDP
	Protocol      uint8
	Checksum      uint16
	SourceIP      net.IP
	DestinationIP net.IP
}

// Packet represents an IPv4 packet.
type Packet struct {
	Header  *Header
	Payload []byte
}
