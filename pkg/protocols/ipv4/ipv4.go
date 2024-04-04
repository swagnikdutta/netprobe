package ipv4

import (
	"net"

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

func CreatePacket(
	version,
	ihl,
	tos,
	flag,
	ttl,
	proto uint8,
	len,
	id,
	fo,
	chkSum uint16,
	src,
	dest net.IP,
	payload []byte,
) (*Packet, []byte, error) {
	p := &Packet{
		Header: &Header{
			Version:        version,
			IHL:            ihl,
			TypeOfService:  tos,
			TotalLength:    len,
			Identification: id,
			Flags:          flag,
			FragmentOffset: fo,
			TTL:            ttl,
			Protocol:       proto,
			Checksum:       chkSum,
			SourceIP:       src,
			DestinationIP:  dest,
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
