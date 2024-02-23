package ipv4

import (
	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

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

	// TODO: This needs to be calculated I think. Try once. Otherwise put it in header
	p.Header.TotalLength = 50

	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing IPv4 packet header")
	}
	p.Header.Checksum = protocols.CalculateChecksum(headerSerialized)

	packetSerialized, err := p.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing IPv4 packet")
	}

	return p, packetSerialized, nil
}
