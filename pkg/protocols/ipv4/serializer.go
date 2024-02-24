package ipv4

import (
	"bytes"

	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

func (h *Header) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	versionIHL := h.Version<<4 | h.IHL
	flagsAndOffset := uint16(h.Flags)<<13 | h.FragmentOffset

	if err := protocols.WriteBinary(buf, versionIHL, h.TypeOfService, h.TotalLength, h.Identification, flagsAndOffset, h.TTL, h.Protocol, h.Checksum, h.SourceIP, h.DestinationIP); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(p.Payload)
	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing IPv4 packet header")
	}
	buf.Write(headerSerialized)

	return buf.Bytes(), nil
}
