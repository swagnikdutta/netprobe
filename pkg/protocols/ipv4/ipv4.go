package ipv4

import (
	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

func calculateTotalLength(p *Packet) (*uint16, error) {
	b, err := p.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing ip packet")
	}
	length := uint16(len(b))
	return &length, nil
}

func CreatePacket(h Header, payload []byte) (*Packet, []byte, error) {
	p := &Packet{
		Header: &Header{
			Version:       h.Version,
			IHL:           h.IHL,
			TTL:           h.TTL,
			Protocol:      h.Protocol,
			SourceIP:      h.SourceIP,
			DestinationIP: h.DestinationIP,
		},
		Payload: payload,
	}

	length, err := calculateTotalLength(p)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error calculating total length of packet")
	}
	p.Header.TotalLength = *length

	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing ip packet header")
	}
	p.Header.Checksum = protocols.CalculateChecksum(headerSerialized)

	packetSerialized, err := p.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing ip packet")
	}

	return p, packetSerialized, nil
}
