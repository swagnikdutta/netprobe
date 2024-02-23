package icmp

import (
	"bytes"

	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

func (h *Header) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := protocols.WriteBinary(buf, h.Type, h.Code, h.Checksum, h.Identifier, h.SequenceNumber); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(p.Payload)
	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing ICMP packet header")
	}
	buf.Write(headerSerialized)

	return buf.Bytes(), nil
}
