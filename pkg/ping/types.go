package ping

import "net"

type Pinger struct {
	sourceIP net.IP
	destIP   net.IP
	count    uint8
}

type ICMPHeader struct {
	Type           uint8
	Code           uint8
	Checksum       uint16
	Identifier     uint16
	SequenceNumber uint16
}

type ICMPPacket struct {
	Header *ICMPHeader
}

type IPv4Header struct {
	Version        uint8
	IHL            uint8
	TypeOfService  uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SourceIP       net.IP
	DestinationIP  net.IP
}

type IPv4Packet struct {
	Header  *IPv4Header
	Payload *ICMPPacket
}
