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

func CreateHeader(
	version uint8,
	ihl uint8,
	tos uint8,
	totalLen uint16,
	identification uint16,
	flags uint8,
	fo uint16,
	ttl uint8,
	proto uint8,
	checksum uint16,
	src net.IP,
	dst net.IP,
) *Header {
	return &Header{
		Version:        version,
		IHL:            ihl,
		TypeOfService:  tos,
		TotalLength:    totalLen,
		Identification: identification,
		Flags:          flags,
		FragmentOffset: fo,
		TTL:            ttl,
		Protocol:       proto,
		Checksum:       checksum,
		SourceIP:       src,
		DestinationIP:  dst,
	}
}

func CreatePacket(header *Header, payload []byte) (*Packet, []byte, error) {
	p := &Packet{
		Header:  header,
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
