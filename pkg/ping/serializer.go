package ping

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

// ICMPHeader represents the header of an ICMP (Internet Control Message Protocol) packet.
// It contains fields for the ICMP message type, code, checksum, identifier, and sequence number.
type ICMPHeader struct {
	Type           uint8
	Code           uint8
	Checksum       uint16
	Identifier     uint16
	SequenceNumber uint16
}

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

// ICMPPacket represents an ICMP packet.
type ICMPPacket struct {
	Header *ICMPHeader
}

func (p *ICMPPacket) Serialize() ([]byte, error) {
	return p.Header.Serialize()
}

// IPv4Header represents the header of an IPv4 Packet.
// This struct defines the fields that make up the IPv4 packet header,
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

// IPv4Packet represents an IPv4 packet.
type IPv4Packet struct {
	Header  *IPv4Header
	Payload *ICMPPacket
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
