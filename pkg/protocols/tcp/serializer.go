package tcp

import (
	"bytes"

	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

func (ph *PseudoHeader) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := protocols.WriteBinary(buf, ph.SourceAddress, ph.DestinationAddress, ph.zero, ph.PTCL, ph.TCPLength); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (h *Header) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	dor := h.DataOffset<<4 | h.Reserved
	if err := protocols.WriteBinary(buf, h.SourcePort, h.DestinationPort, h.SequenceNumber, h.AcknowledgmentNumber, dor, h.Flags, h.Window, h.Checksum, h.UrgentPointer); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(p.Payload)
	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing tcp packet header")
	}
	buf.Write(headerSerialized)
	return buf.Bytes(), nil
}
