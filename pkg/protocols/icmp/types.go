package icmp

// Header represents the header of an ICMP (Internet Control Message Protocol) packet.
// It contains fields for the ICMP message type, code, checksum, identifier, and sequence number.
type Header struct {
	Type uint8
	Code uint8
	// ICMP checksum is calculated on the entire ICMP message(header+data)
	Checksum       uint16
	Identifier     uint16
	SequenceNumber uint16
}

// Packet represents an ICMP packet.
type Packet struct {
	Header  *Header
	Payload []byte
}
