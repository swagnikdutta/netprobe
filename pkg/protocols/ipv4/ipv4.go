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
	version uint8,
	ihl uint8,
	tos uint8,
	len uint16,
	id uint16,
	flag uint8,
	fo uint16,
	ttl uint8,
	proto uint8,
	ch uint16,
	src net.IP,
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
			Checksum:       ch,
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
