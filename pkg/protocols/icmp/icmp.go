package icmp

import (
	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

func CreatePacket(
	hType,
	code uint8,
	checksum,
	id,
	seq uint16,
) (*Packet, []byte, error) {
	p := &Packet{
		Header: &Header{
			Type:           hType,
			Code:           code,
			Checksum:       checksum,
			Identifier:     id,
			SequenceNumber: seq,
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
