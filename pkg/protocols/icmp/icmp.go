package icmp

import (
	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

func CreatePacket(h Header) (*Packet, []byte, error) {
	p := &Packet{
		Header: &Header{
			Type:           h.Type,
			Code:           h.Code,
			Checksum:       h.Checksum,
			Identifier:     h.Identifier,
			SequenceNumber: h.SequenceNumber,
		},
	}

	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing ICMP packet header")
	}
	p.Header.Checksum = protocols.CalculateChecksum(headerSerialized)

	packetSerialized, err := p.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing ICMP packet")
	}

	return p, packetSerialized, nil
}
